# AI investigation evaluation suite

The local adversarial corpus lives in
`tests/evaluations/test_ai_security_corpus.py` and runs with:

```sh
.venv/bin/pytest -q tests/evaluations tests/integrations/test_llm.py
```

It checks the TALARIA-side contract for a grounded positive finding, hostile
retrieved text, rejection of citations that were not supplied, and credential
redaction in model output. The corpus uses fixed fake providers and never sends
repository data or credentials to an external service.

These checks evaluate request construction and deterministic response handling;
they do not measure a model's actual quality, injection resistance, or
repeatability. Provider latency, token usage, and cost are not measured by this
offline suite. A production evaluation run must record the provider/model and
version, exact corpus revision, observed output, citation correctness, safety
violations, latency, provider-reported token usage, and cost using the selected
provider's actual price schedule. Store only redacted outputs and aggregate
metrics; do not retain API keys or raw proprietary source in the evaluation
report.

Keep the local corpus deterministic and review additions as security test data.
Do not make live provider acceptance part of ordinary unit tests.
