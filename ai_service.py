# ai_service.py
import os
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.pydantic_v1 import BaseModel, Field

# 1. Define a more descriptive data structure
class EmailSummary(BaseModel):
    summary: str = Field(description="A 1-2 sentence summary of the email's key point.")
    category: str = Field(description="The most relevant category for the email.")

# 2. Update the function to accept more context
def get_summary_from_grok(sender: str, subject: str, email_text: str) -> dict:
    """
    Uses an improved prompt with LangChain to get an accurate summary and category.
    """
    try:
        model = ChatGroq(model="llama3-8b-8192", temperature=0, api_key=os.environ.get("GROK_API_KEY"))
        parser = JsonOutputParser(pydantic_object=EmailSummary)

        # 3. Create a new, highly-detailed "few-shot" prompt
        prompt = ChatPromptTemplate.from_template(
            template="""You are an expert personal assistant responsible for classifying emails. Analyze the sender, subject, and content to provide a concise summary and assign the most accurate category.

            Follow these category definitions precisely:
            - job_application: A confirmation that a job application was successfully submitted.
            - interview_schedule: A request to schedule an interview or a confirmation of an interview time.
            - job_offer: A formal job offer.
            - application_update: Any update on a job application that is not an offer or interview, such as a rejection or a "next steps" notice.
            - bill: A bill, invoice, or payment reminder.
            - security_alert: An alert about account security, logins, or password changes.
            - promotion: Marketing, sales, or promotional content.
            - other: Anything that does not fit the categories above.

            Respond with ONLY a valid JSON object that follows this schema:
            {format_instructions}

            ---
            EXAMPLES:
            
            Sender: "recruiting@company.com"
            Subject: "Interview Invitation for Software Engineer"
            Content: "Hi, we were impressed with your application and would like to schedule a call..."
            Response: {{"summary": "You have an interview invitation from recruiting@company.com for a Software Engineer role.", "category": "interview_schedule"}}

            Sender: "IBM Talent Acquisition <talent@ibm.com>"
            Subject: "Your IBM Application Status"
            Content: "After careful consideration, IBM has decided to pursue other candidates..."
            Response: {{"summary": "This is an update on your IBM application; they have decided to pursue other candidates for the role.", "category": "application_update"}}
            ---

            Now, process the following email:

            Sender: "{sender}"
            Subject: "{subject}"
            Content: "{email_text}"
            """,
            partial_variables={"format_instructions": parser.get_format_instructions()},
        )

        chain = prompt | model | parser
        result = chain.invoke({"sender": sender, "subject": subject, "email_text": email_text})
        return result
    except Exception as e:
        print(f"Error using LangChain with Grok API: {e}")
        return {"summary": "Error in processing with LangChain.", "category": "error"}