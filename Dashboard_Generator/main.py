import sys
import os
import pandas as pd
import time

# Monkey patch for agno compatibility
try:
    import google.genai.types
    if not hasattr(google.genai.types, 'FileSearch'):
        google.genai.types.FileSearch = type('FileSearch', (), {})
except ImportError:
    pass

from agno.agent import Agent
from agno.models.ollama import Ollama
from agno.knowledge.knowledge import Knowledge
from agno.knowledge.reader.pdf_reader import PDFReader
from agno.knowledge.embedder.ollama import OllamaEmbedder
from agno.vectordb.lancedb import LanceDb, SearchType

def main():
    print("🚀 Initializing Local Agent and Knowledge Base (Ollama)...")
    
    # 1. Knowledge Base using Local Embeddings
    # We use llama3.1 to create the vector representations of your syllabus
    pdf_knowledge_base = Knowledge(
        vector_db=LanceDb(
            table_name="syllabus_local",
            uri="/tmp/lancedb_ollama",
            search_type=SearchType.vector,
            embedder=OllamaEmbedder(id="llama3.1")
        ),
    )
    
    print("📖 Ingesting Syllabus PDF locally...")
    pdf_knowledge_base.insert(
        path="BTech_Syllabus_detailed.pdf",
        reader=PDFReader(chunk=True),
        upsert=False,
        skip_if_exists=True
    )
    
    # 2. Local Agent Definition
    agent = Agent(
        model=Ollama(id="llama3.1"),
        knowledge=pdf_knowledge_base,
        search_knowledge=False,
    )
    
    print("📊 Reading student data...")
    df = pd.read_excel('Sample-Student-Data.xlsx')
    
    for index, row in df.iterrows():
        student_name = row['Student Name']
        print(f"Processing student: {student_name}")
        
        scores = {}
        for col in df.columns:
            if col != 'Student Name':
                max_score = 50 if '(P)' in col else 100
                score = row[col]
                percent = (score / max_score) * 100
                if percent < 60:
                    scores[col] = f"{score}/{max_score} ({percent:.1f}%)"
        
        if not scores:
            remedial_plan_html = "<h3>Remedial Action Plan</h3><p>Excellent performance! No immediate remedial action needed.</p>"
        else:
            prompt = f"""
            The student {student_name} is struggling in the following subjects (score < 60%):
            {scores}

            1. Identify these exact subject codes.
            2. Search the syllabus database for the specific chapters or modules related to these subjects.
            3. Create a 'Remedial Action Plan' referencing specific syllabus topics. Let the tone be encouraging.
            Format in HTML (use <div>, <h3>, <ul>, <li>, <p>). Do NOT use markdown code blocks.
            """
            
            # NO MORE WAITING! Local execution has no rate limits.
            try:
                response = agent.run(prompt)
                remedial_plan_html = response.content.replace("```html", "").replace("```", "")
            except Exception as e:
                print(f"❌ Error for {student_name}: {e}")
                remedial_plan_html = "<p>Error generating local plan. Ensure Ollama is running.</p>"
        
        # Build Dashboard HTML
        score_cards = ""
        for col in df.columns:
            if col != 'Student Name':
                max_score = 50 if '(P)' in col else 100
                score = row[col]
                percent = (score / max_score) * 100
                card_color = "bg-green-100 text-green-800" if percent >= 60 else "bg-red-100 text-red-800"
                score_cards += f"""
                <div class="p-4 rounded-lg shadow {card_color}">
                    <h4 class="font-bold text-lg">{col}</h4>
                    <p class="text-xl">{score} / {max_score}</p>
                    <p class="text-sm">({percent:.1f}%)</p>
                </div>
                """
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>{student_name} - Performance Dashboard</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-50 p-8">
            <div class="max-w-5xl mx-auto bg-white rounded-xl shadow-md overflow-hidden">
                <div class="bg-indigo-600 p-6 text-white text-center">
                    <h1 class="text-3xl font-bold">{student_name}'s Performance Dashboard</h1>
                </div>
                <div class="p-8">
                    <h2 class="text-2xl font-bold mb-4 border-b text-gray-700">Score Summary</h2>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">{score_cards}</div>
                </div>
                <div class="p-8 bg-gray-50">
                    <h2 class="text-2xl font-bold mb-4 border-b text-gray-700">Personalized Study Roadmap</h2>
                    <div class="prose max-w-none">{remedial_plan_html}</div>
                </div>
            </div>
        </body>
        </html>
        """
        
        filename = f"{student_name.replace(' ', '_')}_Dashboard.html"
        with open(filename, 'w') as f:
            f.write(html_template)
        print(f"✅ Generated dashboard: {filename}")

if __name__ == "__main__":
    main()