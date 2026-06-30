# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import json
import os

from loguru import logger

try:
    import aisuite as ai

    AI_KEY = os.getenv("SURFACTANT_AI_API_KEY")
    if AI_KEY is None:
        logger.warning(
            "ai_conn.py: API Key enironment variable (SURFACTANT_AI_API_KEY) not defined. The ai_conn feature will not be used. If using a LLM server without authentication or the LLM configuration is populated in the context file, fill this envionment variable with a dummy value to enable the ai_conn feature."
        )
        AISUITE_AVAILABLE = False
    else:
        AISUITE_AVAILABLE = True
except ImportError:
    AISUITE_AVAILABLE = False
    logger.warning("ai_conn.py: aisuite not installed. The ai_conn feature will not be used.")


class AiConn:
    def __init__(self, provider: str, key_env_name: str, url: str, model: str):
        """
        Handle connections to LLM APIs.

        Args:
            provider (str): Type of API getting used. (Ex. 'openai' for OpenAI-compatible APIs)
            key_env_name (str): Name of the environment variable storing the API key. (Ex. 'SURFACTANT_AI_API_KEY' or 'OPENAI_API_KEY')
            url (str): URL where your API server is located (Ex. 'http://localhost:1234/v1')
            model (str): The string required by your API server to access the correct model. (Ex. 'gemma-4-31b', 'gpt-4o')
        """
        if AISUITE_AVAILABLE:
            self.provider = provider
            self.model = model
            self.key = os.getenv(key_env_name)
            self.url = url
            self.connection = ai.Client(
                provider_configs={self.provider: {"base_url": self.url, "api_key": self.key}}
            )
            self.conn_name = self.provider + ":" + self.model
        else:
            logger.warning(
                "ai_conn.py: You are attempting to initialize an AiConn instance when aisuite is not available."
            )

    def parse_text(self, prompt: str, in_txt: str, json_schema: dict) -> dict | list | None:
        """
        Prompt a LLM and require its response to follow a JSON schema.

        Args:
            prompt (str): Instructions for the LLM.
            in_txt (str): Text for the LLM to parse.
            json_schema (dict): Format for the LLM to follow. Enforcement varies by API.
                Example:
                {
                    "name": "data_extraction",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "User's name"},
                            "age": {"type": "integer"},
                            "preferences": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["name", "age"],
                        "additionalProperties": False,
                    },
                    "strict": True
                }
        """
        if json_schema["schema"]["type"] != "object" and json_schema["schema"]["type"] != "array":
            logger.error(
                f"ai_conn.py: Input JSON schema does not have type 'object' or 'array':\n{json_schema}"
            )
            return None
        if self.provider == "anthropic" or "claude" in self.conn_name:
            full_prompt = f"{prompt}\nUse this JSON schema to parse the text\n{json_schema}\n\nText to parse:\n{in_txt}"
            response = self.connection.chat.completions.create(
                model=self.conn_name,
                messages=[{"role": "user", "content": full_prompt}],
            )
            output = str(response.choices[0].message.content)
            start_index = output.find("{")
            end_index = output.find("}")
            if json_schema["schema"]["type"] == "array":
                start_index = output.find("[")
                end_index = output.find("]")
            try:
                if start_index == -1 or end_index == -1 or end_index <= start_index:
                    raise json.JSONDecodeError(
                        f"Expecting string from LLM to contain both a '{' and '}'", output, 0
                    )
                return json.loads(output[start_index : end_index + 1])
            except json.JSONDecodeError as e:
                # logger.error(f"ai_conn.py: {e} when trying to parse LLM's response to {full_prompt}")
                return None
        else:
            full_prompt = prompt + in_txt
            response = self.connection.chat.completions.create(
                model=self.conn_name,
                messages=[{"role": "user", "content": full_prompt}],
                response_format={"type": "json_schema", "json_schema": json_schema},
            )
            try:
                return json.loads(response.choices[0].message.content)
            except json.JSONDecodeError as e:
                logger.error(
                    f"ai_conn.py: {e} when trying to parse LLM's response to {full_prompt}"
                )
                return None

    def parse_text_complex(self, instructions, in_txt, json_schema, num_tries):
        """
        Look at adding ability to supply number of tries, changing number of lines from in_txt
        """
        return
