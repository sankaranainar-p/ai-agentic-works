import sys

# Monkey patch google.genai.types.FileSearch to bypass agno import issue
import google.genai.types
if not hasattr(google.genai.types, 'FileSearch'):
    google.genai.types.FileSearch = type('FileSearch', (), {})

import os
from agno.agent import Agent
from agno.models.google import Gemini
from agno.knowledge.knowledge import Knowledge
from agno.knowledge.reader.pdf_reader import PDFReader
from agno.knowledge.embedder.google import GeminiEmbedder
from agno.vectordb.lancedb import LanceDb, SearchType

os.environ["GOOGLE_API_KEY"] = "AIzaSyDnkTfsOrewACCvaOg0qPAY3fr_ZHW9CVg"

try:
    pdf_knowledge_base = Knowledge(
        vector_db=LanceDb(
            table_name="syllabus",
            uri="/tmp/lancedb_test",
            search_type=SearchType.vector,
            embedder=GeminiEmbedder()
        ),
        reader=PDFReader(chunk=True)
    )

    print("Inserting knowledge...")
    # Load or insert
    pdf_knowledge_base.insert(path="BTech_Syllabus_detailed.pdf")

    print("Agent setup...")
    agent = Agent(
        model=Gemini(id="gemini-2.0-flash"),
        knowledge=pdf_knowledge_base,
        search_knowledge=True,
    )
    print("Running Agent...")
    response = agent.run("What are the modules for CSEB101?")
    print(response.content)
except Exception as e:
    import traceback
    traceback.print_exc()
