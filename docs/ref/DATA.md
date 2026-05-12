To build the **Semantic SOC Analyst** within your on-device RAM constraint, we will focus on two specific data streams: **Ground Truth** (the NVD) and **Input Telemetry** (System Logs).

---

## **1. The "Ground Truth": NVD Data**

You need a "database of record" that the AI can query to explain why a log is dangerous.

### **Where to find it:**

* **The NVD API 2.0:** This is the gold standard. You can request a free API key from [NIST](https://nvd.nist.gov/developers/request-an-api-key) to get higher rate limits.
* **Fallback (JSON Feeds):** If the API feels too complex for a fast build, download the [NVD JSON 2.0 feeds](https://nvd.nist.gov/vuln/data-feeds) (such as https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.json.zip). These are massive files, so for the project, download the **2024 or 2025** feed only. Unzip the zip file and put the JSON file in `data/`.

### **How to parse and use it:**

1. **Extraction:** Pull only the `cve_id`, `description`, and `cvss_score`.
2. **Chunking:** Do not store the whole NVD. Filter it! For your project, focus only on "Critical" vulnerabilities (CVSS > 9.0) or specific types like "SSH" or "RDP" to keep your vector store small.
3. **Vectorization:** Send the `description` text to the **Hugging Face Inference API**. Store the resulting vector in **Qdrant** with the `cve_id` as metadata.

---

## **2. The "Telemetry": Security Logs**

These are the triggers that the system will analyze.

### **Where to find it:**

* **Kaggle:** Search for "Security Logs" or "SSH Brute Force" datasets. [This dataset](https://www.kaggle.com/datasets/dkhundley/sample-rag-knowledge-item-dataset) is great for small-scale testing.



### **How to parse and use it:**

1. **Regex Parsing:** Use a simple Python script to pull out the **Service** (e.g., `sshd`) and the **Message** (e.g., `Failed password`).
2. **The Query:** Use the "Message" as your semantic search query.
3. **The Loop:**
* **Input:** "Failed password for root."
* **Retrieval:** Qdrant finds a CVE description: *"Multiple failed login attempts in OpenSSH 8.0 allow for brute-forcing..."*
* **Generation:** Groq/Llama 3 combines them: *"Analyst Verdict: High Risk. This log matches patterns for CVE-XXXX-XXXX. Mitigation: Disable root login."*



---

## **3. Implementation Roadmap (The "Builder" Way)**

| Step | Action | Tool |
| --- | --- | --- |
| **Ingestion** | Pull top 500 "Critical" CVEs from 2025. | `nvdlib` or `requests` |
| **Storage** | Store vectors + metadata on disk. | `Qdrant (path="...")` |
| **Parsing** | Extract "Service" name from raw log strings. | `re` (Python Regex) |
| **Evaluation** | Check if the retrieved CVE actually matches the log's service. | `pytest` |

### **"On-Device RAM" Optimization Tip:**

Do not load the NVD data into a Python List or DataFrame. Ingest it directly into **Qdrant** one by one. Once it's in Qdrant (which is running on your disk), your RAM will stay completely clear for the Streamlit UI and the LangChain logic.

**Ready to start the ingestion script?** I can provide the Python code to pull those first 500 CVEs if you're ready.