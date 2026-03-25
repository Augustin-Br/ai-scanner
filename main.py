from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver
from state import AgentState
from nodes import init_recon_node, ai_planner_node, tool_executor_node
import uuid


# ==========================================
# 1. THE ROUTING FUNCTION 
# ==========================================

def should_continue(state: AgentState) -> str:
    """
    Reads the state and decides the next node.
    If there are tools to run -> go to executor.
    If the list is empty -> end the execution.
    """
    actions = state.get("planned_actions", [])
    if len(actions) > 0:
        return "continue"
    else:
        return "end"

# ==========================================
# 2. BUILDING THE GRAPH
# ==========================================

# Initialize the graph builder with our State structure
workflow = StateGraph(AgentState)

# Add our "Specialists" (Nodes)
workflow.add_node("init_recon_node", init_recon_node)
workflow.add_node("ai_planner_node", ai_planner_node)
workflow.add_node("tool_executor_node", tool_executor_node)

# Define the logical flow (Edges)
workflow.add_edge(START, "init_recon_node")
workflow.add_edge("init_recon_node", "ai_planner_node")

# Add the conditional logic
workflow.add_conditional_edges(
    "ai_planner_node",
    should_continue,
    {
        "continue": "tool_executor_node",
        "end": END
    }
)

# Loop back from executor to planner
workflow.add_edge("tool_executor_node", "ai_planner_node")

# ==========================================
# 3. COMPILATION & HUMAN-IN-THE-LOOP
# ==========================================

# We need a checkpointer to save the state when paused
memory = MemorySaver()

# We compile the graph. 
# CRITICAL: interrupt_before pauses the graph right before running the bash commands!
app = workflow.compile(
    checkpointer=memory,
    interrupt_before=["tool_executor_node"]
)

# ==========================================
# 4. EXECUTION
# ==========================================

def main():
    print("--- AutoRecon-AI (LangGraph Edition) ---")
    target_ip = input("Target IP or Domain: ")
    
    session_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": session_id}}
    
    initial_state = {
        "target": target_ip,
        "nmap_results": "",
        "tool_outputs": {},
        "planned_actions": [],
        "final_report": ""
    }
    
    print("\n[*] Starting the Agent...")
    
    for event in app.stream(initial_state, config):
        pass
            
    while True:
        state = app.get_state(config)
        
        if not state.next:
            break 
            
        print("\n" + "="*40)
        print("⏸️  AGENT PAUSED: HUMAN APPROVAL REQUIRED")
        print("="*40)
        
        pending_actions = state.values.get("planned_actions", [])
        print("\nThe AI wants to run the following commands:")
        for action in pending_actions:
            print(f"  [>] Tool: {action.tool}")
            print(f"      Cmd : {action.command}")
            print(f"      Why : {action.reason}")
            
        choice = input("\nApprove execution? [Y/n]: ").strip().lower()
        
        if choice in ['', 'y', 'yes']:
            print("[*] Resuming execution...")
            for event in app.stream(None, config):
                pass
        else:
            print("[-] Execution cancelled by user.")
            break
            
    print("\n[+] Agent finished its job. Happy Hacking!")

if __name__ == "__main__":
    main()