"""MCP (Model Context Protocol) server for repo-audit-scan."""
from typing import Any, Dict, Optional


class MCPServer:
    """MCP server for repo-audit-scan integration."""
    
    def __init__(self):
        """Initialize the MCP server."""
        self.tools = {}
    
    def register_tool(self, name: str, handler: Any) -> None:
        """Register a tool handler.
        
        Args:
            name: Tool name
            handler: Handler function
        """
        self.tools[name] = handler
    
    def get_tool(self, name: str) -> Optional[Any]:
        """Get a tool handler.
        
        Args:
            name: Tool name
            
        Returns:
            Tool handler or None
        """
        return self.tools.get(name)
    
    def list_tools(self) -> Dict[str, Any]:
        """List all registered tools.
        
        Returns:
            Dictionary of tool names and handlers
        """
        return self.tools.copy()


# Global MCP server instance
mcp_server = MCPServer()
