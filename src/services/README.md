We will have two main lambda functions; 
- validation 
- generation 

The generation module can be found in generator.py, this will take an SCP (json) as input and output a generated rego file using Claude 4.5. This is also it's own lambda function 

The validation module takes an SCP (json) and Rego policy as input. It then compares and validates the generated rego file using opa check, opa eval, and Claude. If there is a failure then it is fedback to the generation module with errors (context) forthe LLM to regenerate a correct rego policy. 