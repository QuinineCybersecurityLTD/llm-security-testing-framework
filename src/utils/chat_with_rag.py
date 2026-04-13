"""
Interactive RAG Script
Demonstrates how to use the RAG pipeline for company knowledge base questions.
Run with: python src/chat_with_rag.py
"""
import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from rag.rag_pipeline import RAGPipeline
from adapters.base import ModelConfig, ModelType
from adapters.local_gguf_adapter import LocalGGUFAdapter

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

async def main():
    print("🔧 Initializing Company Chatbot...")

    # 1. Setup the local model (Modify paths/names as needed)
    model_config = ModelConfig(
        name="mistral-local-gguf",
        model_type=ModelType.LOCAL_GGUF,
        model_name=str(PROJECT_ROOT.parent.parent / 'official Work-week 1' / 'My work' / 'llm_security_assessment' / 'models' / 'mistral-7b-instruct-v0.2.Q4_K_M.gguf'),
        parameters={
            "temperature": 0.7,
            "max_tokens": 1000,
            "top_p": 0.95
        },
        timeout=300
    )
    
    model_adapter = LocalGGUFAdapter(model_config)
    await model_adapter.initialize()

    # 2. Setup the RAG Pipeline
    rag_pipeline = RAGPipeline(
        model_adapter=model_adapter,
        chunk_size=512,
        chunk_overlap=50,
        top_k=3,
        similarity_threshold=0.1,  # Lowered threshold so TF-IDF works for short user queries
        system_prompt=(
            "You are a helpful company AI assistant. Answer the user's question using ONLY "
            "the provided context. If the context does not contain enough information "
            "to answer, say so clearly. Do not make up information."
        )
    )

    # 3. Load your company documents
    # Place your company PDFs, DOCX, TXT files inside the knowledge_base folder
    docs_dir = PROJECT_ROOT / "knowledge_base"
    print(f"📖 Loading company documents from: {docs_dir}")
    rag_pipeline.load_documents(str(docs_dir))
    
    # Optional: Build the dense index if you want better retrieval, otherwise it uses lightweight TF-IDF
    # rag_pipeline.build_index()

    print("\n✅ Chatbot ready! Type 'exit' to quit.\n")
    print("-" * 50)

    # 4. Interactive loop
    while True:
        try:
            user_input = input("\nYou: ").strip()
            if user_input.lower() in ['quit', 'exit', 'q']:
                break
            if not user_input:
                continue
                
            print("Chatbot is thinking...\n")
            
            # Query the RAG Pipeline
            response = await rag_pipeline.query(user_input)
            
            print(f"Assistant: {response.generated_response}")
            
            # Optional: Print the source documents used
            sources = [r.chunk.metadata.get('source_file', r.chunk.doc_id) for r in response.retrieved_chunks]
            print("\n  [Sources used: " + ", ".join(sources) + "]")
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    asyncio.run(main())
