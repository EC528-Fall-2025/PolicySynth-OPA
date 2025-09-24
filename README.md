# EC528-Fall-2025-template-repo

**Vision and Goals of the Project:**
======================================
The vision of this project is to create a system that automatically generates OPA policies from existing cloud guardrails, stores them for repeated use in offline or local testing, and integrates them into development pipelines to enforce compliance before deployments occur. A successful solution will enable developers to catch policy violations early, maintain up-to-date governance as cloud rules evolve, and operate efficiently without slowing down workflows.
Goals:
Automatically translate cloud rules (like IAM policies and SCPs) into OPA rules that can be used for checks.
Improve developer experience by detecting cloud policy violations early in the development workflow to reduce deployment failures and debugging overhead.
Keep pre-packaged policies that can be used locally or in pipelines without constantly connecting to the cloud.
Make sure generated policies always match the current cloud rules, so nothing goes out of date.
Make policy generation and checking quick, so it doesn’t slow down development.
Automatically update the OPA policies to stay compliant when the cloud rules change.

**Users/Personas of the Project:** 
======================================
- Developers: 
As a dev, I want to run pre-generated OPA policies locally so that I can validate my IaC code without connecting to the cloud, so that I can get faster feedback 
As a dev, I want to receive clear feedback from OPA validations integrated into my IaC pipeline so I can fix issues before deployment
- Pipeline Administrators: 
As a pipeline admin, I want the system to automatically public synthesized OPA policies into the IaC pipeline so that compliance checks happen automatically without manual intervention
As a pipeline admin, I want the pipeline to synchronize OPA policies whenever cloud guardrails change, so pipeline policies never become stale.
- Compliance Team/Security: 
As the compliance team, I want to verify that the synthesized OPA policies accurately reflect the current cloud guardrails, to ensure that security policies are enforced consistently across environments.
As the compliance team, I want notifications when synchronization between cloud guardrails and OPA policies fails or detects discrepancies.

**Scope and Features of the Project:**
======================================
- In Scope:
AWS Guardrail Discovery. Retrieve governance rules from an AWS account (e.g., Service Control Policies, IAM Policies, Config Rules).
Policy Translation. Automatically translate these cloud rules into equivalent OPA/Rego policies.
Pipeline Integration. Integrate the generated OPA policies into Infrastructure-as-Code pipelines for early compliance checks.
Basic Synchronization. Regenerate and update OPA policies when cloud rules change.
- Out Scope:
Visualization UI. No dashboards or graphical visualization of policies.
Production Enforcement. Project will focus on generating and validating policies, not on enforcing them in production environments
Advanced Drift Detection .Only simple synchronization updates will be considered; complex cloud–OPA drift detection and repair will not be implemented.

**Solution Concept:**
======================================
Below is a high overview of the systems architecture diagram for our solution. 
![IMG_990DABC4A362-1](https://github.com/user-attachments/assets/65214d66-7bfd-493e-acb8-2e399043267b)

Overall we have 5 main components in this project. The guardrail discovery module fetches existing configs within the cloud account that devs/admin have set. Realistically this module would be enacted for every updated configuration. These guardrails are passed to the policy generator to convert these guardrails to OPA/Rego rules, generates them in an applicable format and passes it to the module that distributes and integrates these policies as well to the database to store them. These would become pre-packaged policies cached within the IAC pipeline. Implementing these policies within an IAC pipeline would be the last step with devs being able to check against these pre-packaged policies and then when deploying having a check within the pipeline against any updated policies that are not stored within the pre-packaged policies. 

**Acceptance Criteria:**
======================================
At the end of the project, the Policy Synthesizer engine should be able to successfully discover governance guardrails from a target cloud account (such as AWS SCPs, IAM policies, and Config Rules) and automatically generate equivalent OPA/Rego policies. These synthesized policies must be publishable into an IaC pipeline (e.g., Terraform or CloudFormation) so developers can validate their configurations before deployment. The tool should also support local or offline runs using pre-generated policy packs, enabling developer testing without direct cloud connectivity. Additionally, the system should demonstrate continuous synchronization capabilities so that changes to cloud guardrails are reflected in the generated OPA policies.

**Stretch Goals**
======================================
If time and resources allow, the team will extend the synthesizer to support multi-cloud environments by incorporating Azure Policy and GCP Org Policy translation. Other enhancements may include drift detection to identify mismatches between live cloud policies and synthesized OPA rules, as well as visualization features to provide insight into effective guardrails. Finally, the project may deliver CI/CD pipeline integrations (e.g., GitHub Actions or GitLab CI) that enable policy enforcement during pull request reviews, further embedding compliance into the development workflow.
Pre-packaged policies for offline runs
Github pipeline check


**Release Planning:**
======================================
- Phase 1 - Foundations
Define scope, goals, and descriptions of the project. 
Set up a development environment. 
Deliverable: Architecture and design document, ready-to-build setup. 

- Phase 2 - Core Development 
Build policy discovery for AWS (SCPs, IAM, Config Rules). 
Generate OPA/Rego policies and integrate with Terraform checks. 
Deliverable: Working prototype with local testing support. 

- Phase 3 - Synchronization and Performance
Add synchronization between cloud guardrails and generated OPA. 
Improve performance, error handling, and reporting. 
Deliverable: Stable engine that updates and validates policies reliably. 

- Phase 4 - Release
Package final tool and upload to Github. 
Run demo and present. 
Deliverable: Policy Synthesizer with docs and training. 

**General Comments:**
======================================
N/A 
