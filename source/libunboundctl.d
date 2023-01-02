module libunboundctl;

import std.stdio;
import std.process : Pipe, pipeCreate = pipe;
import std.conv : to;
import core.sys.posix.unistd;
import core.sys.posix.sys.wait;
import std.string : strip;
import std.string : toLower;

public enum RecordType
{
	A,
	AAAA,
	CNAME,
	NS
}

public enum ZoneType
{
	STATIC
}

private ulong cStringLen(char* cString)
{
	int idx = 0;
	while(*(cString+idx))
	{
		idx++;
	}
	return idx;
}

private char* makeCString(string dString)
{
	char[] cString = cast(char[])dString;

	cString.length = cString.length+1;
	cString[cString.length-1] = 0;

	return cString.ptr;
}

public final class UnboundControl
{
	private string endpoint;
	private string unboundCTLPath;
	
	this(string endpoint = "::1@8953", string unboundCTLPath = "/usr/sbin/unbound-control")
	{
		this.endpoint = endpoint;
		this.unboundCTLPath = unboundCTLPath;
	}

	/** 
	 * Runs the command using `unbound-control`
	 * 
	 * Params:
	 *   command = The command to run
	 *   data = Arguments to the command
	 *   cmdOut = A ref string where to place the output from the command
	 *
	 * Returns: true if successful, false otherwise
	 */
	private final bool ctl(string command, string data, ref string cmdOut)
	{
		// Creates a pipe to collect stdout from `unbound-control`
		Pipe pipe = pipeCreate();
		File readEnd = pipe.readEnd();
		File writeEnd = pipe.writeEnd();


		pid_t unboundCtlPid = fork();

		// Child process
		if(cast(int)unboundCtlPid == 0)
		{
			// Close file descriptor 1, make a new file descriptor 1 with fdptr as writeEnd.fileno()
			dup2(writeEnd.fileno(), 1);

			char*[] arguments = [makeCString(unboundCTLPath), makeCString(command), makeCString(data), null];
			if(execv(makeCString(unboundCTLPath), arguments.ptr) == -1)
			{
				writeln("Baad");
				_exit(0);
			}
		}
		// Us (parent process)
		else
		{
			int bruh = waitpid(unboundCtlPid, null, 0);

			if(bruh < 0)
			{
				return false;
			}
			
			// Read at most 500 bytes from the stdout (redirected from `unbound-control`)
			ubyte[] resp;
			resp.length = 500;
			long cnt = read(readEnd.fileno(), resp.ptr, resp.length); //D's read blocks forever, it passes some flags I don't vaab with

			if(cnt < 0)
			{

			}
			else
			{
				resp.length = cnt;
			
				// Strip newline
				cmdOut = strip(cast(string)resp);
			}
		}

		return true;
	}

	public void addLocalData(string domain, RecordType recordType, string value)
	{
		// local_data deavmi.hax. IN A 1.1.1.1
		string dataOut;
		bool status = ctl("local_data", domain~" IN "~to!(string)(recordType)~" "~value, dataOut);

		if(!status)
		{
			debug(dgb)
			{
				writeln("Handle error");
			}
		}
	}

	public void addLocalZone(string zone, ZoneType zoneType)
	{
		string dataOut;
		
		// Convert zonetype from (e.g. `STATIC`) to (e.g. `static`)
		string zoneTypeStr = toLower(to!(string)(zoneType));

		bool status = ctl("local_zone", zone~" "~zoneTypeStr, dataOut);
	}

	public void verbosity(ulong level)
	{
		string dataOut;

		bool status = ctl("verbosity", to!(string)(level), dataOut);
	}
}

unittest
{
	UnboundControl unboundCtl = new UnboundControl("::1@8953");
	unboundCtl.verbosity(5);
	unboundCtl.addLocalZone("hax.", ZoneType.STATIC);
	unboundCtl.addLocalData("deavmi.hax.", RecordType.A, "127.0.0.1");
	unboundCtl.addLocalData("deavmi.hax.", RecordType.AAAA, "::1");
}

