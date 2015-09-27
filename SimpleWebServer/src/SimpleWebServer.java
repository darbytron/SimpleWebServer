/***********************************************************************

   SimpleWebServer.java


   This toy web server is used to illustrate security vulnerabilities.
   This web server only supports extremely simple HTTP GET requests.

   This file is also available at http://www.learnsecurity.com/ntk
 
***********************************************************************/
                                
 
import java.io.*;                                         
import java.net.*;                                        
import java.util.*;                                       
 

public class SimpleWebServer {                            
	private static final int KILOBYTE = 1024;
    /* Run the HTTP server on this TCP port. */           
    private static final int PORT = 8080;                 
 
    /* The socket used to process incoming connections
       from web clients */
    private static ServerSocket dServerSocket;            
   
    public SimpleWebServer () throws Exception {          
    	dServerSocket = new ServerSocket (PORT);          
    }                                                     
 
    public void run() throws Exception {  
    	System.out.println("Listening for requests");
		while (true) {                                   
	 	    /* wait for a connection from a client */
	 	    Socket s = dServerSocket.accept();           
	 
	 	    /* then process the client's request */
	 	    processRequest(s);                           
	 	}                                                
    }                                                    
 
    /* Reads the HTTP request from the client, and
       responds with the file the user requested or
       a HTTP error code. */
    public void processRequest(Socket s) throws Exception { 
    	
    	System.out.println("Request received. Processing...");
	 	/* used to read data from the client */ 
	 	BufferedReader br =                                 
	 	    new BufferedReader (
					new InputStreamReader (s.getInputStream())); 
	 
	 	/* used to write data to the client */
	 	OutputStreamWriter osw =                            
	 	    new OutputStreamWriter (s.getOutputStream());  
	     
	 	/* read the HTTP request from the client */
	 	
	 	String request = br.readLine();
	 	String contentLength  = new String();
	 	
	 	String line;
	 	/* Read the headers */
	 	do{
	 		line = br.readLine();
	 		/* Getting the contentLength */
	 		/* Request must match <headername>: <value> */
		 	if(!line.matches("^.*:\\s.*$")){
		 		System.out.println("Request sucks, header: " + line);
		 		handleError(osw, 400);
		 		return;
		 	}
	 		if(line.startsWith("Content-Length:")){
	 			String split[] = line.split(" ");
	 			contentLength = split[split.length-1];
	 		}
	 		System.out.println(line);
	 	} while(line != null && line.equals(""));
	 	
	 	System.out.println("REQUEST: " + request);
	 	
	 	/* The URL requested needs to be smaller than 1KB */
	 	if(request.getBytes("UTF-8").length > KILOBYTE) {
	 		handleError(osw, 414);
	 		return;
	 	}
	 	
	 	String command = null;                             
	 	String pathname = null;
	 	String httpVersion = null;
	 	
	 	/* parse the HTTP request */
	 	StringTokenizer st = 
		    new StringTokenizer (request, " ");               
	 	if(st.countTokens() >= 3){
	 		command = st.nextToken();                       
		 	pathname = st.nextToken();
		 	httpVersion = st.nextToken();
	 	} else {
	 		handleError(osw, 400);
	 		return;
	 	}
	 	
	 	System.out.println("HTTP-Version: " + httpVersion);
	 	if(httpVersion.equals("HTTP/1.1") || httpVersion.equals("HTTP/1.0")){
	 		
	 	} else {
	 		handleError(osw, 400);
	 		return;
	 	}
	 	File tmpFile = new File("/", pathname);
	 	
	 	if(!(pathname.equals(tmpFile.getCanonicalPath()))){
	 		handleError(osw, 403);
	 		return;
	 	}
	 	
	 
	 	System.out.println("Process parced. Analyzing command...");
		if (command.equals("GET")) {                    
		    /* if the request is a GET
		       try to respond with the file
		       the user is requesting */
		    serveFile (osw,pathname);                   
	 	} else if(command.equals("PUT")) {
	 		/*	if the request is a PUT 
	 		 	try to update the file 
	 		 	the user is specifying. 
	 		 */
	 		
	 		/* Request must include a content-length */
		 	if(contentLength == null) {
		 		handleError(osw, 411);
		 		return;
		 	}
	 		updateFile(osw, pathname, br);
	 		
	 	} else {                                         
		    /* if the request is a NOT a GET or PUT
		       return an error saying this server
		       does not implement the requested command */
		    handleError(osw, 501);
		    return;
	 	}                                               
	 	
	 	/* close the connection to the client */
		
	 	osw.close();                                    
    }          
    
    public void validateHeaders(OutputStreamWriter osw, BufferedReader br){
    	
    }
 
    public void serveFile (OutputStreamWriter osw, String pathname) throws Exception {
	 	FileReader fr=null;                                 
	 	int c=-1;                                           
	 	StringBuffer sb = new StringBuffer();
	       
	 	/* remove the initial slash at the beginning
	 	   of the pathname in the request */
	 	if (pathname.charAt(0)=='/')                        
	 	    pathname=pathname.substring(1);                 
	 	
	 	/* if there was no filename specified by the
	 	   client, serve the "index.html" file */
	 	if (pathname.equals(""))                            
	 	    pathname="index.html";                          
	 
		 	/* try to open file specified by pathname */
		 	try {                                               
		 	    fr = new FileReader (pathname);                 
		 	    c = fr.read();                                  
		 	}                                                   
		 	catch (Exception e) {                               
		 	    /* if the file is not found,return the
		 	       appropriate HTTP response code  */
		 	    osw.write ("HTTP/1.0 404 Not Found\n\n");         
		 	    return;                                         
		 	}                                                   
 
		 	/* if the requested file can be successfully opened
		 	   and read, then return an OK response code and
		 	   send the contents of the file */
		 	osw.write ("HTTP/1.0 200 OK\n\n");                    
		 	while (c != -1) {       
			    sb.append((char)c);                            
		 	    c = fr.read();                                  
		 	}                                                   
		 	osw.write (sb.toString());                                  
    	}                                                       
 
    public void updateFile(OutputStreamWriter osw, String pathname, BufferedReader br) throws Exception {
    	System.out.println("Updating file...");
    	if(pathname.startsWith("/")){
    		pathname = pathname.substring(1);
    	}
    	File f = new File(pathname);
    	if(!(f != null && f.isFile())) {
    		osw.write("Request 201: File created");
    		System.out.println("Creating file");
    	}
    	
    	FileWriter fw = new FileWriter(f);
		BufferedWriter bw = new BufferedWriter(fw);
		String line = new String();
		do {
			line = br.readLine();
			System.out.println("Line: " + line);
			bw.write(line);
		} while(line != null && line.length() != 0);
		fw.close();
		br.close();
    }
    

    
    
    public void handleError(OutputStreamWriter osw, int status) throws Exception{
    	System.out.println("Handling error " + status);
    	String errorMessage;
    	switch(status) {
	    	case 400: {
	    		errorMessage = "Malformed request or header"; //These need to be separated
	    		break;
	    	}
	    	case 403: {
	    		errorMessage = "Forbidden";
	    		break;
	    	}
	    	case 411: {
	    		errorMessage = "Missing content-length header";
	    		break;
	    	}
	    	case 414:
	    		errorMessage = "Too large of a request";
	    		break;
	    	case 501: {
	    		errorMessage = "Not implemented";
	    		break;
	    	}
	    	case 505: {
	    		errorMessage = "Bad HTTP Version";
	    	}
	    	default: {
	    		errorMessage = "Internal error";
	    		break;
	    	}
    	}
    	String responseMessage = String.format("Return status %d: %s", status, errorMessage);
    	osw.write(responseMessage + "\n\n");
    	osw.close();
    }
    
    
    /* This method is called when the program is run from
       the command line. */
    public static void main (String argv[]) throws Exception { 
    	System.out.println("Starting server...");
    	/* Create a SimpleWebServer object, and run it */
    	SimpleWebServer sws = new SimpleWebServer();           
    	sws.run();
    	System.out.println("Server running...");
 	
    }                                                          
}                                                              
