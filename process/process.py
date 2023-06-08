import os
from flask import Flask, request, make_response, jsonify
from dotenv import load_dotenv
from langchain.llms import OpenAI
from langchain.document_loaders import PyPDFLoader
from langchain.vectorstores import Chroma
from langchain.agents.agent_toolkits import (
    create_vectorstore_agent,
    VectorStoreToolkit,
    VectorStoreInfo
)
from threading import Lock
import tenacity

app = Flask(__name__)
load_dotenv()

lock = Lock()
openai_api_key = os.getenv('OPENAI_API_KEY')
llm = OpenAI(temperature=0.1, verbose=True, openai_api_key=openai_api_key)
directory_path = './docs'
file_names = [file for file in os.listdir(directory_path) if file.endswith('.pdf')]

def load_pages_from_files():
    pages = []
    for file_name in file_names:
        file_path = os.path.join(directory_path, file_name)
        loader = PyPDFLoader(file_path)
        pages.extend(loader.load_and_split())
    return pages

def create_chroma_db(pages):
    return Chroma.from_documents(pages, collection_name='rapport')

def create_vectorstore_info(store):
    return VectorStoreInfo(name="rapport", description="rapport", vectorstore=store)

def create_toolkit_and_agent(vectorstore_info):
    toolkit = VectorStoreToolkit(vectorstore_info=vectorstore_info)
    return toolkit, create_vectorstore_agent(llm=llm, toolkit=toolkit, verbose=True)

class VectorStoreContext:
    def __init__(self):
        self.pages = load_pages_from_files()
        self.store = create_chroma_db(self.pages)
        self.vectorstore_info = create_vectorstore_info(self.store)
        self.toolkit, self.agent_executor = create_toolkit_and_agent(self.vectorstore_info)

context = VectorStoreContext()

@tenacity.retry(wait=tenacity.wait_random_exponential(multiplier=1, max=10), stop=tenacity.stop_after_attempt(5))
def process_prompt_with_retry(prompt):
    response = context.agent_executor.run(prompt, language='fr')
    return response

@app.route('/process_prompt', methods=['POST'])
def process_prompt():
    prompt = request.json.get('prompt')
    if not prompt:
        return make_response(jsonify({"error": "No prompt provided"}), 400)
    
    try:
        with lock:
            response = process_prompt_with_retry(prompt)
        return jsonify(response)
    except tenacity.RetryError:
        return make_response(jsonify({"error": "API rate limit exceeded"}), 429)

if __name__ == '__main__':
    app.run()
