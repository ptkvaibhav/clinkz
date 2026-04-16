---
name: review-engagement
description: "After a pipeline run, analyze what worked and what didn't, update persistent KB with lessons learned"
---

Review the results of the most recent Clinkz engagement:

1. Find the latest engagement output in outputs/ directory
2. Parse the findings JSON
3. For each finding:
   - Which _test_* method produced it?
   - What tier was it (1/2/3)?
   - Was it a true positive or likely false positive?
4. For each _test_* method that ran but found nothing:
   - Was the vulnerability actually present? (check against known targets like DVWA)
   - Why might it have missed? (wrong payload, WAF blocked, incorrect endpoint)
5. Summarize:
   - Coverage: X/14 for DVWA (or equivalent for other targets)
   - True positive rate
   - Skills that need improvement
   - New techniques discovered that should be added to persistent KB

If the PersistentKnowledgeBase is accessible, record the engagement results:
- Call record_engagement() with findings summary
- Call record_technique_result() for each test that ran
- Call update_success_rates() to recalculate
