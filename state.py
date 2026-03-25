from typing import List, Dict, Annotated
from typing_extensions import TypedDict
from pydantic import BaseModel, Field
import operator

# ==========================================
# 1. PYDANTIC STRUCTURES 
# ==========================================

class ToolAction(BaseModel):
    """Represents a command to execute suggested by the AI"""
    tool: str = Field(description="Name of the tool (e.g., gobuster, whatweb, nuclei)")
    command: str = Field(description="The exact and complete bash command to execute")
    reason: str = Field(description="Strategic reasoning for choosing this tool")

class AIAnalysis(BaseModel):
    """Strict format expected from the AI after analysis."""
    findings: str = Field(description="Analysis and summary of potential vulnerabilities found")
    next_steps: List[ToolAction] = Field(
        description="List of the next tools to run. Empty if RCE is found or assessment is complete.", 
        default_factory=list
    )

# ==========================================
# 2. LANGGRAPH STATE 
# ==========================================

class AgentState(TypedDict):
    """Shared memory circulating between all nodes."""
    target: str
    nmap_results: str
    
    # Reducer (operator.ior): Merges new tool results with existing ones instead of overwriting.
    tool_outputs: Annotated[Dict[str, str], operator.ior] 
    
    planned_actions: List[ToolAction]
    final_report: str