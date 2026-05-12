This guide is for the coding agent to ensure the final output aligns perfectly with the **"Builder" archetype** and the specific constraints of the assignment.

---

# **Developer Guidelines: Semantic SOC Analyst Build**

## **1. Implementation Priorities (The "Must-Haves")**

* **Modular Architecture:** Do not build a "monolith." Keep the **Ingestion Engine**, **RAG Logic**, and **Streamlit UI** in separate files. This makes it easier to test and explain during the presentation.
* **API-First Inference:** To respect the on-device RAM constraint, **do not** attempt to run large local LLMs (like Llama via Ollama). Use **Groq (Llama 3)** for inference and **Hugging Face Inference API** for embeddings.
* **Hybrid Storage:** Implement **Qdrant** in "On-Disk" mode. Ensure the code checks if the collection already exists before re-ingesting data to save time and compute.
* **Error Handling:** Security tools must be robust. Implement try-except blocks for API timeouts and "No Data Found" scenarios in the vector store.

## **2. Non-Goals (Avoiding Scope Creep)**

* **No User Authentication:** Do not build login screens or user databases. This is a technical demo, not a SaaS product.
* **No Live Log Streaming:** The system should accept **manual log pasting** or **file uploads (.txt/log)**. Real-time packet sniffing is out of scope for this small-scale demo.
* **No Model Fine-tuning:** We are using RAG (Retrieval-Augmented Generation) to provide context. Training or fine-tuning models is unnecessary and exceeds the hardware limits.
* **No Complex CSS:** Use Streamlit’s native components. The "Builder" vibe is about utility and function, not "flashy" animations.

## **3. Testing Strategy (Assignment Requirement)**

The project **must** include a `tests/` directory. The coding agent should generate:

* **Parser Tests:** Verify that the log ingestion logic correctly identifies components (e.g., extracting an IP from a string).
* **Integration Tests:** Use `unittest.mock` to simulate API responses from Groq. We want to test the *logic* of the RAG loop without spending API tokens every time we run a test.
* **The "Grounding" Test:** A specific test case where a benign log is provided. The test passes only if the LLM's response does *not* hallucinate a threat.

## **4. Version Control & Repo Hygiene**

* **Professional README:** The README should not just say "how to run." It must include a **"Technical Strategy"** section explaining the on-device RAM optimization and the choice of RAG for security analysis.
* **Environment Safety:** Include a `.env.example` file. Ensure the `.gitignore` strictly excludes `.env` and any local `qdrant_storage/` folders.
* **Requirements.txt:** Ensure all dependencies (LangChain, Qdrant-client, Streamlit, Python-dotenv) are pinned to stable versions.

## **5. The "Builder" Aesthetic in Code**

* **Comments:** Use professional, docstring-style comments.
* **Logging:** Use the Python `logging` module to print "Analyst" status updates to the console (e.g., `INFO: Querying Qdrant...`, `INFO: Generating Verdict...`). This makes the system feel like a real tool during the demo.

---

### **Final Instruction for the Coding Agent:**

> "Focus on creating a tool that looks like it belongs in a real Security Operations Center. The code should be 'boring' in its reliability and 'exciting' in its intelligence. Prioritize clean logic and automated verification."

**Ready to pass this off?** Once the coding agent gives you the structure, you can start plugging in those API keys and watching the "Analyst" come to life! Should we look at how to frame the "Revised Midterm" next, or focus on the code first?