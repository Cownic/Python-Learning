# Set up virtual environment
python -m venv venv

On Windows:
venv\Scripts\activate

# download required packages
pip install groq python-dotenv

# Create a file named .env in the root of your project folder:
GROQ_API_KEY=your_groq_api_key_here

# Check models that are availability for use
python -c "import os; from dotenv import load_dotenv; from groq import Groq; load_dotenv(); print([m.id for m in Groq().models.list().data])"



# Check no Any to Any Allow
# Check that there is a Any to Any Deny
# To check that production cannot connect to infra range and vice versa
### Production client can only access Zone 1 and not Zone 2
# To check if the firewall rules open random ports, weak / unknown ports (e.g open 80 instead of 443, or opening known reverse shell ports)
# dedup and merge firewall rules
### Combine similar source --> destination
# Check that Management IP is not used
# Check that there is no stateless firewall rules
# Check that there is no legacy services


