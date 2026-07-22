# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

"""
Config Options:
    enable_ai_conn(bool): Enable Connecting to AI APIs. Default is False.
    model(str): REQUIRED: Name of the large language model to use. Must be set by user.
    ai_env_key(str): Environment Variable Name for AI API Key. Default is "SURFACTANT_AI_API_KEY".
    provider(str): Provider backend running the AI model. Default is "ollama".
    url(str): URL to connect to the LLM at. Default is "http://localhost:11434/v1"
"""

import json
import os

from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager


@surfactant.plugin.hookimpl
def settings_name() -> str | None:
    return "ai_conn"


AICONN_AVAILABLE = False

try:
    from aisuite import Client
    from aisuite.provider import ASRError, LLMError

    config = ConfigManager()
    enable_ai_conn = config.get("ai_conn", "enable_ai_conn", False)

    if isinstance(enable_ai_conn, bool) and enable_ai_conn:
        key_env_name = config.get("ai_conn", "ai_env_key", "SURFACTANT_AI_API_KEY")
        AICONN_KEY = os.getenv(key_env_name)
        if AICONN_KEY is None:
            logger.warning(
                f"ai_conn.py: API Key enironment variable ({key_env_name}) not defined. The ai_conn feature will not be used. If using a LLM server without authentication fill this envionment variable with a dummy value to enable the ai_conn feature."
            )
            AICONN_AVAILABLE = False
        else:
            AICONN_AVAILABLE = True
            AICONN_PROVIDER = config.get("ai_conn", "provider", "ollama")
            AICONN_URL = config.get("ai_conn", "url", "http://localhost:11434/v1")
            AICONN_MODEL = config.get("ai_conn", "model")
            if AICONN_MODEL is None:
                AICONN_AVAILABLE = False
                logger.warning(
                    "ai_conn.py: Model not defined in configuration. The ai_conn feature will not be used."
                )
except ImportError:
    AICONN_AVAILABLE = False
    logger.warning("ai_conn.py: aisuite not installed. The ai_conn feature will not be used.")


class AiConn:
    def __init__(self):
        """
        Handle connections to LLM APIs.

        Args:
            provider (str): Type of API getting used. (Ex. 'openai' for OpenAI-compatible APIs)
            key_env_name (str): Name of the environment variable storing the API key. (Ex. 'SURFACTANT_AI_API_KEY' or 'OPENAI_API_KEY')
            url (str): URL where your API server is located (Ex. 'http://localhost:1234/v1')
            model (str): The string required by your API server to access the correct model. (Ex. 'gemma-4-31b', 'gpt-4o')
        """
        # pylint: disable-next=global-statement
        global AICONN_AVAILABLE  # noqa: PLW0603
        if AICONN_AVAILABLE:
            self.provider = AICONN_PROVIDER  # pylint: disable=possibly-used-before-assignment,used-before-assignment
            self.model = AICONN_MODEL  # pylint: disable=possibly-used-before-assignment
            self.key = AICONN_KEY  # pylint: disable=possibly-used-before-assignment
            self.url = AICONN_URL  # pylint: disable=possibly-used-before-assignment,used-before-assignment
            try:
                self.connection = Client(
                    provider_configs={self.provider: {"base_url": self.url, "api_key": self.key}}
                )
            except (ValueError, LLMError, ASRError) as e:
                AICONN_AVAILABLE = False
                logger.error(
                    "ai_conn.py: There was an issue when initializing the LLM connection. Disabling the ai_conn plugin. Error: {e}"
                )
            self.conn_name = self.provider + ":" + self.model
        else:
            logger.warning(
                "ai_conn.py: You are attempting to initialize an AiConn instance when aisuite is not available."
            )

    def parse_text(self, prompt: str, json_schema: dict | None) -> str | dict | list | None:
        """
        Prompt a LLM and require its response to follow a JSON schema.

        Args:
            prompt (str): Instructions for the LLM.
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
        if (
            json_schema
            and json_schema["schema"]["type"] != "object"
            and json_schema["schema"]["type"] != "array"
        ):
            logger.error(
                f"ai_conn.py: Input JSON schema does not have type 'object' or 'array':\n{json_schema}"
            )
            return None
        if self.provider == "anthropic" or "claude" in self.conn_name:
            if json_schema:
                prompt = f"In your response, strictly follow this json_schema with no other fluff/text.\n<json_schema>\n{json_schema}\n</json_schema>{prompt}"

            response = self.connection.chat.completions.create(
                model=self.conn_name,
                messages=[{"role": "user", "content": prompt}],
            )
            output = str(response.choices[0].message.content)
            if json_schema:
                start_index = output.find("{")
                end_index = output.rfind("}")
                if json_schema["schema"]["type"] == "array":
                    start_index = output.find("[")
                    end_index = output.rfind("]")
                try:
                    if start_index == -1 or end_index == -1 or end_index <= start_index:
                        raise json.JSONDecodeError(
                            f"Expecting string from LLM to contain both '{' and '}' or '[' and ']'",
                            output,
                            0,
                        )
                    return json.loads(output[start_index : end_index + 1])
                except json.JSONDecodeError as e:
                    logger.error(f"ai_conn.py: {e} when trying to parse LLM's response to {prompt}")
                    return None
            return output
        try:
            response = self.connection.chat.completions.create(
                model=self.conn_name,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_schema", "json_schema": json_schema},
            )
            return json.loads(response.choices[0].message.content)
        except json.JSONDecodeError as e:
            logger.error(f"ai_conn.py: {e} when trying to parse LLM's response to {prompt}")
        except (ValueError, LLMError, ASRError) as e:
            logger.error(f"ai_conn.py: There was an issue when parsing. Error: {e}")
        return None

    def parse_text_complex(self, instructions, in_txt, json_schema, num_tries):
        """
        Look at adding ability to supply number of tries, changing number of lines from in_txt
        """
        return
