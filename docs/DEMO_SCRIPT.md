# Demo script (~5 minutes)

Prep: `pip install -r requirements.txt`, `streamlit run app.py`, sample mode ON. Take one screenshot per tab into `docs/screenshots/`.

| Time | Screen | Say / do |
|---|---|---|
| 0:00 | Architecture diagram | AWS -> Boto3 collector -> classifier -> risk detector + verifier -> Streamlit |
| 0:30 | Overview | 11 identities, human vs non-human split, severity bars |
| 1:15 | Inventory | Search `backup`; open EC2-Backup-Role, show trust policy (service principal => non-human) |
| 2:00 | Findings | Filter to Critical; open "Role can be assumed by anyone"; show reason + remediation |
| 3:00 | Verification | Show one each: ✅ EC2-Backup-Role -> backup bucket, ⛔ same role -> analytics bucket, ⚠️ Lambda-Report-Role (condition); open evidence |
| 4:15 | Recommendations | Grouped by severity; download CSV |
| 4:40 | Fallback | Untick "Use sample data" with no credentials -> warning banner + sample data shown |
| 5:00 | Wrap-up | Limitations: IAM + S3 only, Conditions not evaluated, no SCPs/boundaries |
