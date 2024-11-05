import os
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import requests
from langchain import LLMChain, PromptTemplate
from langchain.vectorstores import FAISS
from langchain.embeddings import OpenAIEmbeddings
from langchain.text_splitter import CharacterTextSplitter
from langchain.chat_models import ChatOpenAI

@dataclass
class VulnerabilityInfo:
    cve_id: str
    package_name: str
    affected_versions: List[str]
    patch_versions: List[str]
    description: str
    severity: str
    published_date: datetime

class PackageRetriever:
    def __init__(self, bron_api_key: str):
        self.bron_api_key = bron_api_key
        
    def get_package_info(self, cve_id: str) -> VulnerabilityInfo:
        """
        Retrieve package information from BRON database
        """
        # Simulate BRON API call
        # In production, implement actual API call to BRON
        return VulnerabilityInfo(
            cve_id=cve_id,
            package_name="example-package",
            affected_versions=["1.0.0", "1.1.0"],
            patch_versions=["1.1.1", "1.2.0"],
            description="Example vulnerability description",
            severity="HIGH",
            published_date=datetime.now()
        )

class PatchRetriever:
    def __init__(self, osv_api_url: str):
        self.osv_api_url = osv_api_url
        
    def get_patch_details(self, cve_id: str) -> Dict:
        """
        Retrieve patch information from OSV database
        """
        # Simulate OSV API call
        # In production, implement actual API call to OSV
        return {
            "patch_commit": "abc123",
            "patch_files": ["setup.py", "requirements.txt"],
            "patch_description": "Updated dependency versions"
        }

class VulnerabilityRAG:
    def __init__(self, 
                 openai_api_key: str,
                 bron_api_key: str,
                 osv_api_url: str,
                 vector_store_path: str = "vulnerability_index"):
        
        self.package_retriever = PackageRetriever(bron_api_key)
        self.patch_retriever = PatchRetriever(osv_api_url)
        self.embeddings = OpenAIEmbeddings(openai_api_key=openai_api_key)
        self.vector_store = None
        self.vector_store_path = vector_store_path
        
        self.llm = ChatOpenAI(
            temperature=0.2,
            model_name="gpt-4-turbo-preview",
            openai_api_key=openai_api_key
        )
        
        self._initialize_vector_store()
        
    def _initialize_vector_store(self):
        """
        Initialize or load existing vector store
        """
        if os.path.exists(self.vector_store_path):
            self.vector_store = FAISS.load_local(
                self.vector_store_path, 
                self.embeddings
            )
        else:
            # Initialize empty vector store
            self.vector_store = FAISS.from_texts(
                [""], 
                self.embeddings
            )
            
    def _create_context(self, 
                       vuln_info: VulnerabilityInfo, 
                       patch_info: Dict) -> str:
        """
        Create context string from vulnerability and patch information
        """
        return f"""
        CVE ID: {vuln_info.cve_id}
        Package: {vuln_info.package_name}
        Affected Versions: {', '.join(vuln_info.affected_versions)}
        Patch Versions: {', '.join(vuln_info.patch_versions)}
        Severity: {vuln_info.severity}
        
        Vulnerability Description:
        {vuln_info.description}
        
        Patch Details:
        Commit: {patch_info['patch_commit']}
        Modified Files: {', '.join(patch_info['patch_files'])}
        Patch Description: {patch_info['patch_description']}
        """
        
    def generate_remediation_guide(self, cve_id: str) -> str:
        """
        Generate step-by-step remediation guide for a given CVE
        """
        # Retrieve information
        vuln_info = self.package_retriever.get_package_info(cve_id)
        patch_info = self.patch_retriever.get_patch_details(cve_id)
        
        # Create context
        context = self._create_context(vuln_info, patch_info)
        
        # Add to vector store for future reference
        self.vector_store.add_texts([context])
        
        # Save vector store
        self.vector_store.save_local(self.vector_store_path)
        
        # Create prompt template
        prompt_template = """
        Based on the following vulnerability and patch information, create a detailed
        step-by-step guide for remediation. Include commands where appropriate and
        consider potential risks or side effects of the upgrade.

        Context:
        {context}

        Generate a clear, step-by-step remediation guide:
        """
        
        prompt = PromptTemplate(
            template=prompt_template,
            input_variables=["context"]
        )
        
        # Create chain and run
        chain = LLMChain(llm=self.llm, prompt=prompt)
        response = chain.run(context=context)
        
        return response
    
    def search_similar_vulnerabilities(self, 
                                     query: str, 
                                     k: int = 3) -> List[str]:
        """
        Search for similar vulnerabilities in the vector store
        """
        if self.vector_store is None:
            return []
            
        results = self.vector_store.similarity_search(query, k=k)
        return [doc.page_content for doc in results]

# Usage example
if __name__ == "__main__":
    rag = VulnerabilityRAG(
        openai_api_key="your-openai-key",
        bron_api_key="your-bron-key",
        osv_api_url="https://api.osv.dev/v1/"
    )
    
    # Generate remediation guide
    guide = rag.generate_remediation_guide("CVE-2018-10055")
    print(guide)
    
    # Search for similar vulnerabilities
    similar = rag.search_similar_vulnerabilities(
        "python dependency version upgrade"
    )
    print("\nSimilar vulnerabilities:", similar)