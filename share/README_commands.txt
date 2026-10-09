DATASET PACKAGE - HOW TO READ THE DATA
======================================
This package has recorded data from TWO different applications. Everything is read from
local files: no API key, no running server and no internet are needed. The scripts only
return the recorded data; they do not analyse, score or label anything.

    share/
      resume_datasets/     Resume/JD screening service   (dataset_a, dataset_b, dataset_c)
        test_datasets.py
        application_profile.json
        datasets/
      rag_datasets/        Support-ticket RAG chatbot    (rag_a, rag_b)
        test_rag_datasets.py
        application_profile.json
        rag_a/  rag_b/

Requires Python 3.9 or newer. Run each script from inside its own folder.

Start with the application profile of each app: it says what the application is, who its
users are, what components it has and where its stated policies are recorded.


COMMANDS  (same for both scripts; swap the script and dataset names)
--------------------------------------------------------------------
Resume service (run inside share/resume_datasets):

    python test_datasets.py                          list datasets
    python test_datasets.py profile                  application profile
    python test_datasets.py dataset_a                list the flows in a dataset
    python test_datasets.py dataset_a login          every recorded item of a flow
    python test_datasets.py dataset_a login 1        one item only (counting from 0)
    python test_datasets.py dataset_a login --body   response bodies only

RAG chatbot (run inside share/rag_datasets):

    python test_rag_datasets.py                      list datasets
    python test_rag_datasets.py profile              application profile
    python test_rag_datasets.py rag_a                list the flows in a dataset
    python test_rag_datasets.py rag_a chat           every recorded item of a flow
    python test_rag_datasets.py rag_a chat 1         one item only (counting from 0)
    python test_rag_datasets.py rag_a chat --body    response bodies only


FROM PYTHON  (same function names in both scripts)
--------------------------------------------------
    from test_datasets import (list_datasets, list_flows, get_exchanges,
                               get_response, get_application_profile)
    # for the chatbot: from test_rag_datasets import (...same names...)

    get_application_profile()                  dict describing the application
    list_datasets()                            ['dataset_a', 'dataset_b', 'dataset_c']
    list_flows("dataset_a")                    flow names available in that dataset
    get_exchanges("dataset_a", "evaluate")     every item of a flow (list of dicts)
    get_response("dataset_a", "evaluate", 0)   one item: its response, or the item itself


WHAT AN ITEM LOOKS LIKE
-----------------------
HTTP flows hold request/response pairs:

    {"request":  {"method": "POST", "path": "/chat", "role": "customer", "body": {...}},
     "response": {"status": 200, "headers": {"X-Request-ID": "..."}, "body": {...}}}

"role" is who made the request. X-Request-ID links an HTTP call to its audit-log events.

Trace flows (internal records, not HTTP) hold plain objects. In the chatbot data, retrieval,
prompts, llm_responses and tool_calls are keyed by request_id and query_id, which also
appear in the chat flow and in the audit log.


FLOWS
-----
Resume service (16 flows per dataset):
    health, login, upload_resume, evaluate, evaluations, evaluation_detail, evidence,
    evidence_verify, stored_files, audit_log, audit_log_verify, access_replay, retention,
    compliance_rules, compliance_report, app_log

RAG chatbot (14 flows per dataset):
    health, login, chat, retrieval, prompts, llm_responses, tool_calls, ticket_corpus,
    audit_log, audit_log_verify, app_log, access_matrix, retention, residency_config

Flows named *_verify, access_replay, retention and compliance_report hold the application's
own recorded results. They are recorded outputs, not ground truth; check them against the raw
data in the other flows.

Audit-log entries carry "prev_hash" and "hash" (SHA-256 over the entry's fields sorted by key,
without the "hash" field itself, compact JSON separators), forming a chain.


ERRORS
------
    error: Unknown dataset 'x'. Available: ...     check the dataset name
    error: Unknown flow 'x' in <dataset>. ...      list the flows first
    error: ... index N is out of range             use a smaller index, or omit it
