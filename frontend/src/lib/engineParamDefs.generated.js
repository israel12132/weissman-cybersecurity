/**
 * AUTO-GENERATED — node scripts/generate_engine_param_defs.mjs
 * Supplemental scan parameters for production engines without explicit PARAM_DEFS.
 * Do not edit by hand; regenerate after registry changes.
 */
export const GENERATED_PARAM_DEFS = {
  "prototype_pollution": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "xxe": [
    {
      "key": "oast_domain",
      "label": "OAST Callback Domain",
      "type": "text",
      "defaultVal": "",
      "placeholder": "token.oast.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "ssti": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cache_poisoning": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "ai_adversarial_redteam": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_redteam": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "adversarial_ml": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "autonomous_pentest": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "http_feedback_fuzz": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "serverless_attack": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "scada_ics": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "avionics_adsb_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "maritime_ais_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ev_charging_ocpp_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "smart_grid_dlms_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rail_signaling_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "building_automation_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "robotics_ros2_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ot_sis_triton_attack": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "iot_firmware": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ble_rf": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "timing_sidechannel": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "antiforensics": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "stealth_engine": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "pqc_scanner": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "crypto_engine": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "kill_chain": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "deception_honeypot": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "zero_day_prediction": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "poe_synthesis": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "microsecond_timing": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "llm_jailbreak": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "prompt_injection_chain": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "model_inversion_attack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "ai_supply_chain_attack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_agent_hijack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "rag_poisoning_engine": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "adversarial_examples": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "data_poisoning_engine": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "deepfake_synthesis": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_dos_attack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "multimodal_ai_attack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "ai_bias_exploit": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "gpt_plugin_attack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "autonomous_ai_escape": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_memory_extraction": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "neural_backdoor_detect": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "ai_watermark_bypass": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "federated_learning_attack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_red_team_advanced": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "model_stealing_engine": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "apt28_techniques": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "apt29_techniques": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "apt41_techniques": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "lazarus_group_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "volt_typhoon_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "scattered_spider_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "salt_typhoon_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "fin7_techniques": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "conti_ransomware_ttps": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "lockbit_techniques": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "cl0p_techniques": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "blackcat_alphv_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "midnight_blizzard_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "earth_longzhi_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "equation_group_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "sandworm_techniques": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "carbon_spider_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "wizard_spider_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "unc2452_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "unc3944_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "quantum_sovereign_nexus": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "lambda_escape": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "terraform_state_attack": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloudformation_injection": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "service_mesh_attack": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_audit_evasion": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "ecr_registry_attack": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "multi_cloud_pivot": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_worm_propagation": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "serverless_injection": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_data_exfil": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_network_attack": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_privilege_persistence": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "padding_oracle_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "hash_extension_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ecdsa_nonce_bias": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rsa_timing_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "mfa_bypass_engine": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "credential_stuffing": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "kerberos_attack_suite": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "zero_trust_bypass": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "pki_hierarchy_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "session_fixation_adv": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "password_hash_crack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "quantum_key_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "password_spray_advanced": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dns_exfil_engine": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "http_covert_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "cloud_exfil_engine": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "encrypted_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "acoustic_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "em_exfil_engine": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "optical_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "cache_timing_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "keyboard_acoustic": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "screen_capture_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "clipboard_hijack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "database_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "email_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "insider_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "storage_covert_channel": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "bootkit_uefi": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "fileless_malware_engine": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "polymorphic_engine": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "botnet_c2_engine": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "keylogger_engine": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "spyware_stalkerware": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "worm_propagation": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rce_exploit_engine": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "persistence_mechanism": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "lateral_movement_engine": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "data_staging_engine": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "exploit_kit_engine": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "trojan_dropper": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "macro_malware": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "android_malware_engine": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ios_exploit_engine": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "mobile_mitm": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ssl_pinning_bypass": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "android_intent_attack": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ios_url_scheme_attack": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "mobile_overlay_attack": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "sim_swap_engine": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "mobile_banking_trojan": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "app_store_attack": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "mdm_bypass_engine": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "bluetooth_mobile_attack": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "nfc_relay_attack": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "mobile_spyware_engine": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "react_native_attack": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "arp_spoofing_engine": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "vlan_hopping_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dhcp_attack_engine": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dns_cache_poisoning": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dns_rebinding": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "can_bus_surface": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ntp_amplification": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "snmp_exploitation": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rdp_attack_engine": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ldap_injection_engine": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "voip_sip_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ss7_signaling_probe": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "wifi_attack_engine": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "bluetooth_attack_engine": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ospf_bgp_hijack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "mpls_vpn_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "lte_5g_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "network_covert_channel": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "wpa3_attack_engine": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "tor_exit_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "protocol_downgrade": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "network_baseline_anomaly": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "packet_injection_engine": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "network_tap_advanced": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "multicast_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "nat_traversal_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dnp3_attack": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "bacnet_attack": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "zigbee_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "iec61850_attack": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "satellite_comm_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rfid_nfc_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "threat_intel_fusion": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "attack_surface_quantify": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "external_exposure_supreme": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "identity_attack_chain": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "pipeline_to_runtime_risk": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "adversarial_threat_emulation": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dark_web_monitor": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "passive_dns_forensics": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "vishing_engine": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "smishing_engine": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "qr_phishing": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "deepfake_voice_engine": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "business_email_compromise": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "watering_hole_attack": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "pretexting_engine": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "insider_threat_engine": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "brand_impersonation": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "fake_update_engine": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "linkedin_phishing": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "callback_phishing": [
    {
      "key": "oast_domain",
      "label": "OAST Callback Domain",
      "type": "text",
      "defaultVal": "",
      "placeholder": "token.oast.example.com"
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "physical_social_eng": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "typosquatting_phishing": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "process_hollowing": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "process_inventory": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "usb_enumeration": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "living_off_land": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "heap_exploitation": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "github_actions_attack": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "compiler_backdoor": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "open_source_backdoor": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "cdn_poisoning_engine": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "software_signing_attack": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "build_system_compromise": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dependency_confusion": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "update_hijacking": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "sbom_forgery_engine": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "third_party_api_attack": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "iac_supply_chain": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "cors_misconfiguration": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "swagger_abuse": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "soap_injection": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "odata_injection": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "css_injection": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "template_injection_adv": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "http_parameter_pollution": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "api_mass_assignment": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "clickjacking_engine": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "subdomain_takeover": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "file_inclusion_rfi": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "deserialization_net": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "api_rate_limit_bypass": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "graphql_subscription_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "webrtc_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "browser_extension_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "web3_dapp_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "api_gateway_bypass": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "liminal_boundary": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "anti_debug_evasion": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "av_bypass_engine": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "azure_devops_attack": [
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "blockchain_trace": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "cloud_iam_escalation": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_metadata_ssrf": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "coap_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "com_hijacking": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "darkweb_intel": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dll_hijacking_engine": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dns_tunneling_c2": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "docker_image_poison": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "eks_attack": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "financial_osint": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "firmware_emulation_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "gcp_privilege_attack": [
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "github_secret_scan": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "graphql_deep_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "grpc_reflection_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "hmi_attack": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "http2_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "https_c2_masquerade": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "icmp_covert": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "idor_advanced": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "industrial_protocol_fuzz": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "iot_shodan_scan": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ipv6_advanced_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "jit_spray": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "job_posting_osint": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "jwt_advanced_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "kubernetes_rbac_escape": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "log_tampering_engine": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "maven_supply_chain": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "memory_forensics_evasion": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "metadata_harvest": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "modbus_attack": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "mqtt_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "network_traffic_masking": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "nosql_deep_injection": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "npm_package_attack": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "oauth_advanced_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ollama_fuzz": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "opcua_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "parent_pid_spoof": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "patent_recon": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "plc_logic_attack": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "profinet_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "pypi_supply_chain": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ransomware_emulation": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "rootkit_surface_probe": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rop_chain_engine": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "s3_bucket_attack": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "saml_advanced_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "sandbox_evasion": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "satellite_recon": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "secrets_manager_attack": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "steganography_c2": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "telecom_osint": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "timing_evasion_engine": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "web_cache_poison_adv": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "rce_chain": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "active_directory": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "c2_emulation": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "lateral_movement": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "data_exfiltration": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "memory_corruption": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "browser_exploitation": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "deepfake_genai": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "container_escape": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "wireless_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "cloud_ransomware": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "firmware_exploit": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "physical_security": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "vuln_chaining": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "sqli_advanced": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "log4shell_scan": [
    {
      "key": "oast_domain",
      "label": "OAST Callback Domain",
      "type": "text",
      "defaultVal": "",
      "placeholder": "token.oast.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "kernel_exploit": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "vlan_bypass": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "malware_persistence": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "insider_threat": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "post_exploitation": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "cloud_lateral": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "process_injection": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "api_fuzzing": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "smb_relay": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "graphql_injection": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "container_k8s_escape": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "web_cache_poison": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "xxe_injection": [
    {
      "key": "oast_domain",
      "label": "OAST Callback Domain",
      "type": "text",
      "defaultVal": "",
      "placeholder": "token.oast.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "ldap_injection": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "side_channel": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ssrf_chain": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "jwt_attacks": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "bgp_hijacking": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rce_deserialization": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "active_directory_enum": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ransomware_sim": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "waf_ids_bypass": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "siem_evasion": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "mobile_pentest": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cors_exploit": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "js_prototype_pollution": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "ipsec_vpn_audit": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "5g_security": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "firmware_emulation": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "cloud_storage_audit": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "devsecops_scan": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "wasm_reverse": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "bluetooth_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "oauth_abuse": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "clickjacking": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "email_spoofing": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "satellite_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ai_poisoning": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "smart_contract_audit": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "automotive_can_bus": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "zero_click_exploit": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "biometric_spoofing": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "quantum_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "devsecops_secrets": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "threat_hunting_apt": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "cloud_identity_attack": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "ci_cd_poisoning": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "api_gateway_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "deception_evasion": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rag_poisoning": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "graphene_os_bypass": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "obfuscated_c2": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "hardware_implant": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "serverless_cold_start": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "active_directory_cs": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "data_pipeline_attack": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "exfil_ai_inference": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "cloud_waf_bypass": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "telco_ss7_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "deepweb_intel": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "network_tap_implant": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "gitops_attack": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "compliance_gap_scan": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dns_enum": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "social_media_recon": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "shodan_mass_scan": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "cert_transparency": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "email_harvest": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "github_recon": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "geoint": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "network_topology_map": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "employee_profiling": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "wayback_recon": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "xss_advanced": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "csrf_exploit": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "path_traversal": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "business_logic_flaw": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "race_condition_web": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "oauth_pkce_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "mass_assignment": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "web_cache_deception": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "api_versioning_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "nosql_injection": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "deserialization_java": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "open_redirect": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "host_header_injection": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "graphql_batching": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "ai_model_backdoor": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_context_overflow": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "ai_supply_chain": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "adversarial_image": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_dos": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_privacy_leak": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "agentic_ai_escape": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_system_prompt_leak": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "s3_bucket_enum": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "imds_ssrf": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "lambda_layer_inject": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_trail_disable": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cross_account_pivot": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "gke_rbac_exploit": [
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "azure_ad_attack": [
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "terraform_state_steal": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_cost_dos": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_logging_blind": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "ecr_image_poison": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "cloud_function_escape": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "modbus_exploit": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "plc_logic_bomb": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "lora_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "lorawan_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "hmi_exploit": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "can_fd_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ics_historian_attack": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rootkit_implant": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "timestomping": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "log_wiping": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dll_hijacking": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "fileless_malware": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "syscall_evasion": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "amsi_bypass": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "polymorphic_payload": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "password_crack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "tls_downgrade": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "totp_bruteforce": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ntlm_relay": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "golden_ticket": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "hsm_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "pki_cert_forge": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "key_derivation_flaw": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "arp_spoofing": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "icmp_covert_channel": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "snmp_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ospf_bgp_manipulation": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "rdp_exploit": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dns_tunneling": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "dhcp_starvation": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "wifi_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "npm_typosquatting": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "build_artifact_tamper": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "package_signing_bypass": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "vendored_code_attack": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "code_review_bypass": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "update_mechanism_hijack": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "advanced_persistence": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "apt_lateral_movement": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "nation_state_ttps": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "zero_day_chain": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "apt_c2_infra": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "long_haul_exfil": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "full_breach_sim": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "watering_hole": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "supply_chain_apt": [
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "destructive_wiper": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "tpm_firmware_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "cold_boot_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "evil_maid_engine": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "thunderbolt_dma_attack": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "voltage_glitch_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "badusb_hid_attack": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "hardware_wallet_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "jtag_swd_exploitation": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "medical_device_exploit": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "implantable_device_hack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "hospital_hl7_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "agentic_framework_attack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_function_call_hijack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "multi_agent_subversion": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "llm_guardrail_bypass": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "mcp_server_exploit": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "synthetic_identity_fraud": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "ai_model_provenance_attack": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "repo_url",
      "label": "Repository URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "https://github.com/org/infra"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "sdn_controller_exploit": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "nfv_mano_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "network_slice_isolation_bypass": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "harvest_now_decrypt_later": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "pqc_implementation_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "lattice_crypto_attack": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "microsegmentation_bypass": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "continuous_auth_evasion": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "sase_security_bypass": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "webauthn_fido2_bypass": [
    {
      "key": "domain",
      "label": "Target Domain (AD/DNS)",
      "type": "text",
      "defaultVal": "",
      "placeholder": "corp.example.com"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ai_cloud_escalation_chain": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "social_supply_chain_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "ot_it_lateral_chain": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "mobile_backend_chain": [
    {
      "key": "platform",
      "label": "Platform",
      "type": "select",
      "defaultVal": "both",
      "options": [
        "both",
        "android",
        "ios"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "data_deanonymization": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "behavioral_biometric_attack": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "location_pattern_analysis": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "differential_privacy_exploit": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "c2_rotation_engine": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "detection_gap_exploiter": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "opsec_intelligence_engine": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "tactic_chain_synthesizer": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "ar_vr_attack_engine": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "edge_computing_exploit": [
    {
      "key": "aws_cross_account_role_arn",
      "label": "AWS Cross-Account Role ARN",
      "type": "text",
      "defaultVal": "",
      "placeholder": "arn:aws:iam::123:role/WeissmanReadOnly"
    },
    {
      "key": "aws_external_id",
      "label": "AWS External ID",
      "type": "password",
      "defaultVal": "",
      "placeholder": "external-id"
    },
    {
      "key": "gcp_project",
      "label": "GCP Project ID",
      "type": "text",
      "defaultVal": "",
      "placeholder": "my-project"
    },
    {
      "key": "azure_subscription_id",
      "label": "Azure Subscription ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "azure_tenant_id",
      "label": "Azure Tenant ID",
      "type": "text",
      "defaultVal": ""
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "blockchain_bridge_exploit": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "api_all_vectors_engine": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "cookies",
      "label": "Session Cookies",
      "type": "password",
      "defaultVal": "",
      "placeholder": "session=..."
    },
    {
      "key": "auth_header",
      "label": "Authorization Header",
      "type": "password",
      "defaultVal": "",
      "placeholder": "Bearer eyJ..."
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    }
  ],
  "threat_model_automation": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "attack_graph_traversal": [
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "github_token",
      "label": "GitHub Token (optional)",
      "type": "password",
      "defaultVal": "",
      "placeholder": "ghp_..."
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "prometheus_hyperion_nexus": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "sap_erp_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "mainframe_zos_attack": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "malvertising_seo_poison": [
    {
      "key": "campaign_name",
      "label": "Campaign Name",
      "type": "text",
      "defaultVal": "",
      "placeholder": "Red Team Q2"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "infostealer_emulation": [
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "printer_mfp_attack": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "radius_nac_bypass": [
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ot_passive_active_safety": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "ot_crown_jewel_path": [
    {
      "key": "protocol_strict",
      "label": "OT Protocol Strict",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    },
    {
      "key": "ports",
      "label": "Ports / Port Range",
      "type": "text",
      "defaultVal": "top",
      "placeholder": "top | 80,443,8080"
    },
    {
      "key": "probe_mode",
      "label": "OT Probe Mode",
      "type": "select",
      "defaultVal": "safe_read",
      "options": [
        "passive",
        "safe_read",
        "active_validation"
      ]
    },
    {
      "key": "depth",
      "label": "Probe Depth",
      "type": "select",
      "defaultVal": "3",
      "options": [
        "1",
        "2",
        "3",
        "4",
        "5"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "advanced_c2_covert_exfil": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "honey_routing_gateway": [
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "timeout_ms",
      "label": "Probe Timeout (ms)",
      "type": "number",
      "defaultVal": "8000",
      "min": 500,
      "max": 60000
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "evidence_mode",
      "label": "Evidence Mode",
      "type": "select",
      "defaultVal": "standard",
      "options": [
        "standard",
        "strict",
        "forensic"
      ]
    }
  ],
  "stealthy_persistence_evasion": [
    {
      "key": "stealth_mode",
      "label": "Stealth Mode",
      "type": "select",
      "defaultVal": "low",
      "options": [
        "off",
        "low",
        "high"
      ]
    },
    {
      "key": "stealth_level",
      "label": "Stealth Level (1-5)",
      "type": "number",
      "defaultVal": "3",
      "min": 1,
      "max": 5
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    }
  ],
  "prompt_injection_brake": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "jailbreak_cognitive_engine": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ],
  "rag_poisoning_guard": [
    {
      "key": "llm_base_url",
      "label": "LLM Base URL",
      "type": "text",
      "defaultVal": "",
      "placeholder": "http://127.0.0.1:11434/v1"
    },
    {
      "key": "llm_model",
      "label": "LLM Model",
      "type": "text",
      "defaultVal": "",
      "placeholder": "gpt-4o"
    },
    {
      "key": "intensity",
      "label": "Scan Intensity",
      "type": "select",
      "defaultVal": "normal",
      "options": [
        "light",
        "normal",
        "aggressive"
      ]
    },
    {
      "key": "max_findings",
      "label": "Max Findings",
      "type": "number",
      "defaultVal": "200",
      "min": 1,
      "max": 5000
    },
    {
      "key": "safe_mode",
      "label": "Safe Mode (no destructive exec)",
      "type": "select",
      "defaultVal": "true",
      "options": [
        "true",
        "false"
      ]
    }
  ]
}
