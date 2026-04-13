"""
Dense Vector Store — Drop-in Replacement for TFIDFVectorStore
Uses sentence-transformers for dense embeddings with cosine similarity retrieval.
Supports semantic chunking and optional cross-encoder re-ranking.

Falls back gracefully to TF-IDF if sentence-transformers is not available.
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

try:
    import numpy as np
except ImportError:
    np = None

try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False

try:
    from sentence_transformers import CrossEncoder
    HAS_CROSS_ENCODER = True
except ImportError:
    HAS_CROSS_ENCODER = False


@dataclass
class DocumentChunk:
    """A single chunk of a document with metadata."""
    chunk_id: str
    content: str
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[Any] = None  # np.ndarray when available


class SemanticChunker:
    """Split documents into semantically meaningful chunks."""

    def __init__(
        self,
        max_chunk_tokens: int = 256,
        overlap_tokens: int = 32,
        split_pattern: str = r"(?<=[.!?])\s+|\n\n",
    ):
        self.max_chunk_tokens = max_chunk_tokens
        self.overlap_tokens = overlap_tokens
        self.split_pattern = split_pattern

    def chunk(self, text: str, source: str = "unknown") -> List[DocumentChunk]:
        """Split text into overlapping semantic chunks."""
        # Split on sentence / paragraph boundaries
        sentences = re.split(self.split_pattern, text.strip())
        sentences = [s.strip() for s in sentences if s.strip()]

        chunks: List[DocumentChunk] = []
        current = []
        current_len = 0

        for sentence in sentences:
            word_count = len(sentence.split())
            if current_len + word_count > self.max_chunk_tokens and current:
                chunk_text = " ".join(current)
                chunk_id = hashlib.md5(chunk_text.encode()).hexdigest()[:12]
                chunks.append(DocumentChunk(
                    chunk_id=f"{source}_{chunk_id}",
                    content=chunk_text,
                    source=source,
                ))
                # Overlap: keep last N tokens worth of sentences
                overlap_budget = self.overlap_tokens
                overlap = []
                for s in reversed(current):
                    if overlap_budget <= 0:
                        break
                    overlap.insert(0, s)
                    overlap_budget -= len(s.split())
                current = overlap
                current_len = sum(len(s.split()) for s in current)

            current.append(sentence)
            current_len += word_count

        # Final chunk
        if current:
            chunk_text = " ".join(current)
            chunk_id = hashlib.md5(chunk_text.encode()).hexdigest()[:12]
            chunks.append(DocumentChunk(
                chunk_id=f"{source}_{chunk_id}",
                content=chunk_text,
                source=source,
            ))

        return chunks


class DenseVectorStore:
    """
    Dense embedding vector store using sentence-transformers.
    
    Drop-in replacement for the TFIDFVectorStore in rag_pipeline.py.
    Falls back to TF-IDF-like behaviour if sentence-transformers is unavailable.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        use_cross_encoder: bool = False,
        cross_encoder_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2",
    ):
        self.model_name = model_name
        self.use_cross_encoder = use_cross_encoder and HAS_CROSS_ENCODER
        self.chunks: List[DocumentChunk] = []
        self.embeddings: Optional[Any] = None  # np.ndarray matrix
        self.chunker = SemanticChunker()

        # Load models
        if HAS_SENTENCE_TRANSFORMERS:
            print(f"  Loading dense embedding model: {model_name}")
            self.encoder = SentenceTransformer(model_name)
            if self.use_cross_encoder:
                print(f"  Loading cross-encoder: {cross_encoder_model}")
                self.reranker = CrossEncoder(cross_encoder_model)
            else:
                self.reranker = None
        else:
            print("  ⚠ sentence-transformers not available, using TF-IDF fallback")
            self.encoder = None
            self.reranker = None

    def add_documents(self, documents: List[str], sources: Optional[List[str]] = None) -> int:
        """Add documents to the store, chunking and embedding them."""
        if sources is None:
            sources = [f"doc_{i}" for i in range(len(documents))]

        new_chunks = []
        for doc, src in zip(documents, sources):
            new_chunks.extend(self.chunker.chunk(doc, source=src))

        self.chunks.extend(new_chunks)

        # Compute embeddings
        if self.encoder and np is not None:
            texts = [c.content for c in self.chunks]
            self.embeddings = self.encoder.encode(texts, convert_to_numpy=True, show_progress_bar=False)
            # Normalise for cosine similarity
            norms = np.linalg.norm(self.embeddings, axis=1, keepdims=True)
            norms[norms == 0] = 1  # avoid div by zero
            self.embeddings = self.embeddings / norms
        else:
            self.embeddings = None

        return len(new_chunks)

    def search(self, query: str, top_k: int = 5) -> List[Tuple[DocumentChunk, float]]:
        """
        Search the vector store using dense embeddings + optional re-ranking.
        
        Returns list of (DocumentChunk, similarity_score) tuples.
        """
        if not self.chunks:
            return []

        if self.encoder and self.embeddings is not None and np is not None:
            # Dense embedding search
            query_emb = self.encoder.encode([query], convert_to_numpy=True)
            query_norm = np.linalg.norm(query_emb)
            if query_norm > 0:
                query_emb = query_emb / query_norm

            # Cosine similarity (already normalised)
            scores = np.dot(self.embeddings, query_emb.T).flatten()

            # Get top candidates (more than top_k for re-ranking)
            candidate_k = min(top_k * 3, len(self.chunks)) if self.reranker else top_k
            top_indices = np.argsort(scores)[::-1][:candidate_k]

            candidates = [(self.chunks[i], float(scores[i])) for i in top_indices]

            # Re-rank with cross-encoder if available
            if self.reranker and len(candidates) > 0:
                pairs = [[query, c.content] for c, _ in candidates]
                rerank_scores = self.reranker.predict(pairs)
                reranked = sorted(
                    zip(candidates, rerank_scores),
                    key=lambda x: x[1],
                    reverse=True,
                )
                candidates = [(chunk, float(score)) for (chunk, _), score in reranked[:top_k]]
            else:
                candidates = candidates[:top_k]

            return candidates
        else:
            # Fallback: simple keyword matching
            return self._keyword_search(query, top_k)

    def _keyword_search(self, query: str, top_k: int) -> List[Tuple[DocumentChunk, float]]:
        """Basic TF-IDF-like fallback when sentence-transformers unavailable."""
        query_terms = set(query.lower().split())
        scored = []
        for chunk in self.chunks:
            chunk_terms = set(chunk.content.lower().split())
            overlap = len(query_terms & chunk_terms)
            score = overlap / max(len(query_terms), 1)
            scored.append((chunk, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def get_stats(self) -> Dict[str, Any]:
        """Return store statistics."""
        return {
            "total_chunks": len(self.chunks),
            "model": self.model_name if self.encoder else "tfidf-fallback",
            "has_dense_embeddings": self.embeddings is not None,
            "has_cross_encoder": self.reranker is not None,
            "embedding_dim": self.embeddings.shape[1] if self.embeddings is not None else 0,
        }
