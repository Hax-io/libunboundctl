module libunboundctl;

import std.stdio;
import std.process : Pipe, pipeCreate = pipe;
import std.conv : to, ConvException;
import core.sys.posix.unistd;
import core.sys.posix.sys.wait;
import std.string : strip;
import std.string : toLower, toUpper, cmp;
import std.array;

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

		// Creates a pipe to collect stderr from `unbound-control`
		// TODO: Add this in

		// Fork from here
		pid_t unboundCtlPid = fork();

		// Child process
		if(cast(int)unboundCtlPid == 0)
		{
			// Close file descriptor 1, make a new file descriptor 1 with fdptr as writeEnd.fileno()
			dup2(writeEnd.fileno(), 1);

			char*[] arguments = [makeCString(unboundCTLPath), makeCString("-s"), makeCString(endpoint), makeCString(command), makeCString(data), null];
			if(execv(makeCString(unboundCTLPath), arguments.ptr) == -1)
			{
				writeln("Baad");
				_exit(0);
			}
		}
		// Us (parent process)
		else
		{
			int wstatus;
			int pid = waitpid(unboundCtlPid, &wstatus, 0);

			// Close the write end of the pipe, allowing us to not block for eternity
			writeEnd.close();

			if(WEXITSTATUS(wstatus) != 0)
			{
				// TODO: Set `cmdOut` to stderr text
				cmdOut = "TODO Stderr text";
				return false;
			}
			else
			{
				// FIXME: This should read till EOF (-1) - so put this in a loop
				ubyte[] fullResponse;
				ubyte[] temp;

				while(true)
				{
					// Read 500 chunks at a time
					temp.length = 500;
					long cnt = read(readEnd.fileno(), temp.ptr, temp.length); //D's read blocks forever, it passes some flags I don't vaab with
					writeln(cnt);


					if(cnt <= 0)
					{
						break;
					}
					else
					{
						fullResponse ~= temp[0..cnt];
					}
				}

			
				// Strip newline
				cmdOut = strip(cast(string)fullResponse);
				

				return true;
			}
		}

		return false;
	}

	public void addLocalData(Record record)
	{
		// local_data deavmi.hax. IN A 1.1.1.1
		string domain = record.domain;
		RecordType recordType = record.recordType;
		string value = record.value;

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

	public void removeLocalZone(string zone)
	{
		string dataOut;
		
		bool status = ctl("local_zone_remove", zone, dataOut);
	}

	public void removeLocalData(string domain)
	{
		string dataOut;
		
		bool status = ctl("local_data_remove", domain, dataOut);
	}

	public void verbosity(ulong level)
	{
		string dataOut;

		bool status = ctl("verbosity", to!(string)(level), dataOut);
	}

	public Zone[] listLocalZones()
	{
		string zoneData;

		bool status = ctl("list_local_zones", "", zoneData);

		// If the records were returned into the `zoneData` string
		if(status)
		{
			Zone[] zones;
			foreach(string zoneInfo; split(zoneData, "\n"))
			{
				string[] zoneInfoSegments = split(zoneInfo, " ");

				Zone curZone;
				curZone.zone = zoneInfoSegments[0];
				curZone.zoneType = to!(ZoneType)(toUpper(zoneInfoSegments[1]));
				zones ~= curZone;
			}

			return zones;
		}
		// If an error occurred
		else
		{
			// TODO: Throw an exception here
			throw new Exception("Error occurred");
		}
	}

	public Record[] listLocalData()
	{
		string recordData;

		bool status = ctl("list_local_data", "", recordData);

		// If the records were returned into the `zoneData` string
		if(status)
		{
			Record[] records;
			foreach(string recordInfo; split(recordData, "\n"))
			{
				// SKip the empty lines
				if(cmp(recordInfo, "") == 0)
				{
					continue;
				}
				else
				{
					string[] recordInfoSegments = split(recordInfo, "\t");

					Record curRecord;
					string domain = recordInfoSegments[0];
					ulong ttl = to!(ulong)(recordInfoSegments[1]);

					try
					{
						RecordType recordType = to!(RecordType)(recordInfoSegments[3]);

						curRecord.domain = domain;
						curRecord.ttl = ttl;
						curRecord.recordType = recordType;

						if(recordType == RecordType.NS || recordType == RecordType.A || 
						  recordType == RecordType.AAAA || recordType == RecordType.CNAME ||
						  recordType == RecordType.PTR
						)
						{
							curRecord.value = recordInfoSegments[4];
						}
						else if(recordType == RecordType.SOA)
						{
							string[] soaSegments = split(recordInfoSegments[4], " ");
							curRecord.value = soaSegments[0];

							// TODO: Implement SOA handling
							string soaEmail = soaSegments[1];
							ulong[] soaTuple = [to!(ulong)(soaSegments[2]),
												to!(ulong)(soaSegments[3]),
												to!(ulong)(soaSegments[4]),
												to!(ulong)(soaSegments[5]),
												to!(ulong)(soaSegments[6])];
							
							curRecord.soaEmail = soaEmail;
							curRecord.soaTuple = soaTuple;
						}
						else
						{
							writeln("This should never happen");
							assert(false);
						}
					}
					catch(ConvException e)
					{
						// TODO: Throw an exception here
						throw new Exception("Error occurred");
					}
					
					records ~= curRecord;
				}
				
			}

			return records;
		}
		// If an error occurred
		else
		{
			// TODO: Throw an exception here
			throw new Exception("Error occurred");
		}
	}
}

public enum RecordType
{
	A,
	AAAA,
	CNAME,
	NS,
	SOA,
	PTR
}

public enum ZoneType
{
	STATIC,
	REDIRECT
}

public struct Zone
{
	ZoneType zoneType;
	string zone;
}

public struct Record
{
	string domain;
	RecordType recordType;
	string value;
	ulong ttl;
	string soaEmail;
	ulong[] soaTuple;
}

unittest
{
	UnboundControl unboundCtl = new UnboundControl("::1@8953");
	unboundCtl.verbosity(5);
	unboundCtl.addLocalZone("hax.", ZoneType.STATIC);
	unboundCtl.addLocalData(Record("deavmi.hax.", RecordType.A, "127.0.0.1"));
	unboundCtl.addLocalData(Record("deavmi.hax.", RecordType.AAAA, "::1"));

	unboundCtl.removeLocalData("deavmi.hax.");

	unboundCtl.removeLocalZone("hax.");
}

unittest
{
	UnboundControl unboundCtl = new UnboundControl("::1@8953");

	try
	{
		Zone[] zones = unboundCtl.listLocalZones();
		writeln(zones);

		Record[] records = unboundCtl.listLocalData();
		writeln(records);
	}
	catch(Exception e)
	{
		assert(false);
	}
	
}

unittest
{
	UnboundControl unboundCtl = new UnboundControl("::1@8952");
	try
	{
		unboundCtl.listLocalZones();
		assert(false);
	}
	catch(Exception e)
	{
		assert(true);
	}
}