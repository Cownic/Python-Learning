### Set up virtual environment
python -m venv venv

On Windows:
venv\Scripts\activate

# download required packages
pip install groq python-dotenv


### Create a file named .env in the root of your project folder:
GROQ_API_KEY=your_groq_api_key_here


#### Check models that are availability for use
python -c "import os; from dotenv import load_dotenv; from groq import Groq; load_dotenv(); print([m.id for m in Groq().models.list().data])"
