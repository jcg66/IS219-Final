To move from "great idea" to "working code," we need to lock in the technical architecture. Working with on-device RAM is a constraint, so our final decisions focus on offloading memory-heavy tasks to specialized APIs while keeping the logic and storage local.

### **Final Technical Decisions**

* **Database:** **Qdrant (Local)**. We will use the `path` parameter (e.g., `QdrantClient(path="data/qdrant_db")`) to run it in **on-disk mode**. This prevents the vector store from ballooning your RAM.
* **Embeddings:** **Hugging Face Inference API**. Instead of loading a 500MB model into your local memory, we’ll use an API call to their serverless endpoints to get vectors.
* **Inference:** **Groq API (Llama 3 8B or 70B)**. This gives you lightning-fast speed with zero local memory cost.
* **Testing:** We will use **Pytest**. We’ll implement "Gold Set" testing—comparing the RAG output against a set of known security facts to ensure it doesn't hallucinate.

---

### **Coding Agent Brief: Semantic SOC Analyst**

**To the Coding Agent:** Please build a professional, small-scale RAG application based on the following specifications. This is for a final portfolio piece; the code must be clean, modular, and include automated tests.

#### **1. Project Overview**

Build a "Semantic SOC Analyst" that ingests security logs and compares them against the National Vulnerability Database (NVD) using RAG to identify threats.

#### **2. Technical Stack**

* **Orchestration:** LangChain
* **Vector Store:** Qdrant (On-disk mode)
* **Inference:** Groq (Llama 3)
* **Embeddings:** Hugging Face Inference API
* **UI:** Streamlit

#### **3. Functional Requirements**

* **Data Ingestion:** A script to pull a sample of CVE data from the NVD (use a local JSON if the API is slow) and store it in Qdrant.
* **Log Parser:** A module to handle raw strings from SSH/Syslog entries.
* **RAG Pipeline:** 1.  Vectorize the input log.
2.  Query Qdrant for the top 3 similar CVEs.
3.  Pass CVE context + log to Groq with a system prompt: *"You are a Senior SOC Analyst. Use only the provided context to analyze the log. If no match is found, state that no known vulnerability was identified."*
* **Frontend:** A simple dashboard to paste a log and see the "Analyst Verdict."

#### **4. Testing Requirements (Non-Negotiable)**

Implement a `/tests` directory using `pytest`:

* **Unit Test:** Ensure the log parser correctly extracts IP addresses/timestamps.
* **Integration Test:** Mock the Groq API to ensure the RAG loop returns a response.
* **Grounding Test:** A test case where a "benign" log is submitted to ensure the system doesn't flag it as a threat (False Positive test).

#### **5. Repository Structure**

```text
/IS219-Final-Project    # Root folder for the Semantic SOC Analyst project
├── /docs               # Project management and documentation
├── /data               # Local Qdrant storage & NVD samples
├── /src
│   ├── ingestion.py    # Vectorizing NVD data
│   ├── analyst.py      # Main RAG logic
│   └── app.py          # Streamlit UI
├── /tests              # Pytest suite
├── .env                # API Keys (GROQ_API_KEY, HF_TOKEN)
├── requirements.txt
└── README.md           # Professional documentation

```

---

### **Next Steps**

1. **Get your API Keys:** You’ll need a free [Groq Cloud](https://console.groq.com/) key and a [Hugging Face](https://huggingface.co/settings/tokens) token.
2. **Run the Report:** You can now pass the section above to your coding agent of choice.
3. **The "Builder" Vibe:** While the agent codes, keep your "Builder" archetype in mind. Make sure the README it generates isn't generic—it should scream "I built this to be powerful and efficient on a local machine."

How are you feeling about the technical complexity? Does the "Hybrid-Local" approach make sense for your current setup?