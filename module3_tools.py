import json
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()
client = genai.Client()


# 1. Functie locala determinista cu dactilografiere si docstring
def lookup_cve_details(cve_id: str) -> str:
    """Look up the CVSS severity score and technical summary for a given CVE identifier.

    Args:
        cve_id: The official CVE string, for example 'CVE-2024-3094'.
    """
    mock_db = {
        "CVE-2024-3094": {
            "cvss": 10.0,
            "affected": "xz-utils 5.6.0 and 5.6.1",
            "summary": "Malicious backdoor injected into liblzma build process hooking RSA_public_decrypt in sshd.",
        },
        "CVE-2021-44228": {
            "cvss": 10.0,
            "affected": "Apache Log4j2 2.0-beta9 to 2.14.1",
            "summary": "Unauthenticated remote code execution via JNDI lookup in logged messages (Log4Shell).",
        },
    }
    record = mock_db.get(cve_id.upper(), {"error": f"No record found for {cve_id}"})
    return json.dumps(record)


def run_manual_tool_roundtrip(user_prompt: str):
    # Dezactivam apelarea automata (automatic_function_calling=False)
    # pentru a construi manual secventa in 4 pasi
    config = types.GenerateContentConfig(
        system_instruction="You are a cybersecurity assistant. Always use tools to verify CVE data.",
        tools=[lookup_cve_details],
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        temperature=0.0,
    )

    messages = [types.Content(role="user", parts=[types.Part.from_text(text=user_prompt)])]

    print("--- Pasul 1 & 2: Trimitere prompt si inspectare cerere Tool ---")
    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=messages,
        config=config,
    )

    if response.function_calls:
        tool_call = response.function_calls[0]
        print(f"[LLM A cerut Tool] Nume: {tool_call.name} | Argumente: {tool_call.args}\n")

        # Pasul 3: Executia locala a functiei
        if tool_call.name == "lookup_cve_details":
            tool_output = lookup_cve_details(**tool_call.args)
            print(f"[Rezultat Functie Locala]:\n{tool_output}\n")

            # Pasul 4: Trimiterea raspunsului inapoi la LLM
            # a) Adaugam raspunsul intermediar al modelului (cand a cerut tool-ul) in istoric
            messages.append(response.candidates[0].content)

            # b) Adaugam raspunsul local al functiei ca raspuns de tip tool
            messages.append(
                types.Content(
                    parts=[
                        types.Part.from_function_response(
                            name=tool_call.name,
                            response={"result": tool_output}
                        )
                    ]
                )
            )

            # c) Facem al doilea apel LLM pentru sinteza finala
            print("--- Pasul 4c: Sinteza finala a modelului ---")
            final_res = client.models.generate_content(
                model="gemini-3.5-flash-lite",
                contents=messages,
                config=config,
            )
            print(f"[Raspuns Final LLM]:\n{final_res.text}")
    else:
        print(f"[Raspuns Direct LLM]:\n{response.text}")


if __name__ == "__main__":
    run_manual_tool_roundtrip("What is CVE-2024-3094, what versions are affected, and how severe is it?")