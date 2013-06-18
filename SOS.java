package sos;

import java.util.*;

/**
 * This class contains the simulated operating system (SOS). Realistically it
 * would run on the same processor (CPU) that it is managing but instead it uses
 * the real-world processor in order to allow a focus on the essentials of
 * operating system design using a high level programming language.
 * 
 * 
 * @author Preben Ingvaldsen
 * @author Et Begert
 * @author Aaron Dobbe
 * @author Sam Golloway
 * @author Viet Phan
 * @author Janel Raab
 * @author Ben Rumptz
 * @author Kyle DeFrancia
 * 
 * @version April 17, 2013
 * 
 */

public class SOS implements CPU.TrapHandler
{
    // ======================================================================
    // Constants
    // ----------------------------------------------------------------------

    // These constants define the system calls this OS can currently handle
    public static final int SYSCALL_EXIT = 0; /* exit the current program */
    public static final int SYSCALL_OUTPUT = 1; /* outputs a number */
    public static final int SYSCALL_GETPID = 2; /* get current process id */
    public static final int SYSCALL_OPEN = 3; /* access a device */
    public static final int SYSCALL_CLOSE = 4; /* release a device */
    public static final int SYSCALL_READ = 5; /* get input from device */
    public static final int SYSCALL_WRITE = 6; /* send output to device */
    public static final int SYSCALL_EXEC    = 7;    /* spawn a new process */
    public static final int SYSCALL_YIELD   = 8;    /* yield the CPU to another process */
    public static final int SYSCALL_COREDUMP = 9; /*
                                                   * print process state and
                                                   * exit
                                                   */    

    // Success and error code constants
    public static final int SUCCESS = 0;
    public static final int DEVICE_NOT_FOUND = -1;
    public static final int DEVICE_NOT_SHARABLE = -2;
    public static final int DEVICE_ALREADY_OPEN = -3;
    public static final int DEVICE_NOT_OPEN = -4;
    public static final int DEVICE_READ_ONLY = -5;
    public static final int DEVICE_WRITE_ONLY = -6;
    
    /**
     * This process is used as the idle process' id
     */
    public static final int IDLE_PROC_ID    = 999;
    
    //Default size for process queue
    public static final int INIT_HEAP_SIZE = 50;
    
    //Maximum number of CPU ticks a process can starve for
    public static final int MAX_STARVE_TIME  = 30000;
    

    // ======================================================================
    // Member variables
    // ----------------------------------------------------------------------

    /**
     * This flag causes the SOS to print lots of potentially helpful status
     * messages
     **/
    public static final boolean m_verbose = true;

    /**
     * The CPU the operating system is managing.
     **/
    private CPU m_CPU = null;

    /**
     * The RAM attached to the CPU.
     **/
    private RAM m_RAM = null;

    /**
     * The current process run by the CPU.
     **/
    private ProcessControlBlock m_currProcess = null;

    /**
     * All devices currently registered.
     **/
    private Vector<DeviceInfo> m_devices = null;
    
    /**
     * All program objects available to OS
     */
    private Vector<Program> m_programs = null;
    
    /**
     * ID for next process that is loaded
     */
    private int m_nextProcessID = 1001;
    
    /**
     * List of all current process in RAM and in one of the major states
     */
    private Vector<ProcessControlBlock> m_processes = null;

    /**
     * PriorityQueue (really a max heap) of ready processes, highest priority first
     */
    private PriorityQueue<ProcessControlBlock> m_readyQueue = null;
    
    /**
     * List of all blocks in RAM not allocated to a process
     */
    private Vector<MemBlock> m_freeList = null;
    
    /**
     * True if a program was loaded into RAM correctly
     */
    private boolean m_programLoaded = false;
    
    /**
     * Memory management unit
     */
    private MMU m_MMU = null;
    
    /*
     * ======================================================================
     * Constructors & Debugging
     * ----------------------------------------------------------------------
     */

    /**
     * The constructor does nothing special
     */
    public SOS(CPU c, RAM r, MMU m)
    {
        // Init member list
        m_CPU = c;
        m_RAM = r;
        m_CPU.registerTrapHandler(this);
        m_currProcess = new ProcessControlBlock(m_nextProcessID);
        m_devices = new Vector<DeviceInfo>();
        m_programs = new Vector<Program>();
        m_processes = new Vector<ProcessControlBlock>();
        m_readyQueue = new PriorityQueue<ProcessControlBlock>(INIT_HEAP_SIZE, new MaxHeapifier());        
        m_MMU = m;        
        m_freeList = new Vector<MemBlock>();
        
        //all available memory is free, so add it to the list
        //available memory starts on the page immediately after the page table
        int addr = forceMultipleOfPageSize(m_MMU.getNumPages());        
        int size = m_MMU.getSize() - addr;
        m_freeList.add(new MemBlock(addr, size));
        
        //setup page table for the MMU
        initPageTable();
        
    }// SOS ctor

    /**
     * Does a System.out.print as long as m_verbose is true
     **/
    public static void debugPrint(String s)
    {
        if (m_verbose)
        {
            System.out.print(s);
        }
    }

    /**
     * Does a System.out.println as long as m_verbose is true
     **/
    public static void debugPrintln(String s)
    {
        if (m_verbose)
        {
            System.out.println(s);
        }
    }

    /*
     * ======================================================================
     * Memory Block Management Methods
     * ----------------------------------------------------------------------
     */
    
    /**
     * compact
     * 
     * Helper method to compact the processes in RAM.  Moves all processes to
     * bottom of RAM, leaving all unallocated space at the top.
     * 
     * After this method is called, m_freeList will contain exactly one MemBlock
     */
    private void compactRAM()
    {        
    	m_freeList.clear();
    	
    	//sort processes by base address
    	Collections.sort(m_processes);
    	
    	//start adding processes at beginning of available RAM, above page table
    	int nextAddr = forceMultipleOfPageSize(m_MMU.getNumPages());
    	
    	//iterate through all processes, adding them on top of each other
    	for (ProcessControlBlock pcb : m_processes)
    	{
    		pcb.move(nextAddr);
    		nextAddr = forceMultipleOfPageSize(pcb.getRegisterValue(CPU.LIM));    
    	}
    	
    	//create one giant MemBlock that contains all remaining free space
    	MemBlock newFreeBlock = new MemBlock(nextAddr, m_MMU.getSize() - nextAddr);
    	m_freeList.add(newFreeBlock);
    }

    /**
     * allocBlock
     * 
     * Decides where to load a process
     * 
     * @param size of the process to be loaded
     * @return address of the block allocated for the process
     */
    private int allocBlock(int size)
    {
    	//keep track of how much free space exists in RAM
        int freespace = 0;
        
    	//search m_freeList for a suitable hole
    	for (MemBlock block : m_freeList)
    	{
    		if(size <= block.getSize())
    		{
    			//use this free block
    			m_freeList.remove(block);
    			
    			//add any leftover space back into free list
    			int blockAddr = block.getAddr() + size;
    			int blockSize = block.getSize() - size;
    			if (blockSize != 0) m_freeList.add(new MemBlock(blockAddr, blockSize));
    			
    			return block.getAddr();
    		}
    		else 
    		{
    			freespace += block.getSize();
    		}
    	}
    	
    	//if no blocks big enough, but we have enough space, compact and look again
    	if (freespace >= size) compactRAM();
    	//else process won't fit
    	else return -1;
    	
    	if (m_freeList.size() == 1)
    	{
    		MemBlock block = m_freeList.firstElement();
    		
    		if(size <= block.getSize())
    		{
    			//use this free block
    			m_freeList.remove(block);
    			
    			//add any leftover space back into free list
    			int blockAddr = block.getAddr() + size;
    			int blockSize = block.getSize() - size;
    			if (blockSize != 0) m_freeList.add(new MemBlock(blockAddr, blockSize));
    			
    			return block.getAddr();
    		}
    	}
    	
    	//still not enough space somehow
        return -1;
        
        
    }//allocBlock

    /**
     * freeCurrentProcessMemBlock
     * 
     * Adjusts m_freeList to account for the fact that current process is
     * about to be killed.  
     */
    private void freeCurrProcessMemBlock()
    {
    	int size = m_CPU.getLIM() - m_CPU.getBASE(); //size of current process
        int address = m_CPU.getBASE(); //base address of current process
        
        //merge any contiguous free space
        for(int index = 0; index < m_freeList.size(); index = index +1)
        {
        	MemBlock mb = m_freeList.elementAt(index);
        	
        	//check for free space below the currentProcess
        	if(mb.getAddr() + mb.getSize() == m_CPU.getBASE())
        	{
        		address = mb.getAddr();
        		size = size + mb.getSize();
        		m_freeList.remove(mb);
        	}
        	
        	//check for free space above the current Process
        	if(mb.getAddr() == m_CPU.getLIM())
        	{
        		size = size + mb.getSize();
        		m_freeList.remove(mb);
        	}
        }
        
        m_freeList.add(new MemBlock(address, size));
        
    }//freeCurrProcessMemBlock
    

    /**
     * printMemAlloc                 *DEBUGGING*
     *
     * outputs the contents of m_freeList and m_processes to the console and
     * performs a fragmentation analysis.  It also prints the value in
     * RAM at the BASE and LIMIT registers.  This is useful for
     * tracking down errors related to moving process in RAM.
     *
     * SIDE EFFECT:  The contents of m_freeList and m_processes are sorted.
     *
     */
    private void printMemAlloc()
    {
        //If verbose mode is off, do nothing
        if (!m_verbose) return;

        //Print a header
        System.out.println("\n----------========== Memory Allocation Table ==========----------");
        
        //Sort the lists by address
        Collections.sort(m_processes);
        Collections.sort(m_freeList);

        //Initialize references to the first entry in each list
        MemBlock m = null;
        ProcessControlBlock pi = null;
        ListIterator<MemBlock> iterFree = m_freeList.listIterator();
        ListIterator<ProcessControlBlock> iterProc = m_processes.listIterator();
        if (iterFree.hasNext()) m = iterFree.next();
        if (iterProc.hasNext()) pi = iterProc.next();

        //Loop over both lists in order of their address until we run out of
        //entries in both lists
        while ((pi != null) || (m != null))
        {
            //Figure out the address of pi and m.  If either is null, then assign
            //them an address equivalent to +infinity
            int pAddr = Integer.MAX_VALUE;
            int mAddr = Integer.MAX_VALUE;
            if (pi != null)  pAddr = pi.getRegisterValue(CPU.BASE);
            if (m != null)  mAddr = m.getAddr();

            //If the process has the lowest address then print it and get the
            //next process
            if ( mAddr > pAddr )
            {
                int size = pi.getRegisterValue(CPU.LIM) - pi.getRegisterValue(CPU.BASE);
                System.out.print(" Process " + pi.processId +  " (addr=" + pAddr + " size=" + size + " words");
                System.out.print(" / " + (size / m_MMU.getPageSize()) + " pages)" );
                System.out.print(" @BASE=" + m_MMU.read(pi.getRegisterValue(CPU.BASE))
                                 + " @SP=" + m_MMU.read(pi.getRegisterValue(CPU.SP)));
                System.out.println();
                if (iterProc.hasNext())
                {
                    pi = iterProc.next();
                }
                else
                {
                    pi = null;
                }
            }//if
            else
            {
                //The free memory block has the lowest address so print it and
                //get the next free memory block
                System.out.println("    Open(addr=" + mAddr + " size=" + m.getSize() + ")");
                if (iterFree.hasNext())
                {
                    m = iterFree.next();
                }
                else
                {
                    m = null;
                }
            }//else
        }//while
            
        //Print a footer
        System.out.println("-----------------------------------------------------------------");
        
    }//printMemAlloc
    
    
    /**
     * forceMultipleOfPageSize
     * 
     * Helper method that takes a given address and updates it to the next
     * multiple of the page size.
     * 
     * @param addr  address to change
     * @return a corrected address
     */
    private int forceMultipleOfPageSize(int addr)
    {
        if (addr % m_MMU.getPageSize() != 0)
        {
            int remainder = addr % m_MMU.getPageSize();
            addr = addr + (m_MMU.getPageSize() - remainder);
        }
        return addr;
    }
    

    /*
     * ======================================================================
     * Device Management Methods
     * ----------------------------------------------------------------------
     */

    // None yet!

    /*
     * ======================================================================
     * Process Management Methods
     * ----------------------------------------------------------------------
     */

    /**
     * printProcessTable      **DEBUGGING**
     *
     * prints all the processes in the process table
     */
    private void printProcessTable()
    {
        debugPrintln("");
        debugPrintln("Process Table (" + m_processes.size() + " processes)");
        debugPrintln("======================================================================");
        for(ProcessControlBlock pi : m_processes)
        {
            debugPrintln("    " + pi);
        }//for
        debugPrintln("----------------------------------------------------------------------");

    }//printProcessTable
    

    /**
     * removeCurrentProcess
     * 
     * removes the current process from the process table and arranges for a
     * new one to be scheduled
     * 
     */
    public void removeCurrentProcess()
    {
        m_processes.remove(m_currProcess);
        freeCurrProcessMemBlock();
        m_currProcess = null;
        scheduleNewProcess();
        
    }//removeCurrentProcess
    

    /**
     * getRandomProcess
     *
     * selects a non-Blocked process at random from the ProcessTable.
     *
     * @return a reference to the ProcessControlBlock struct of the selected process
     * -OR- null if no non-blocked process exists
     */
    ProcessControlBlock getRandomProcess()
    {
        //Calculate a random offset into the m_processes list
        int offset = ((int)(Math.random() * 2147483647)) % m_processes.size();
            
        //Iterate until a non-blocked process is found
        ProcessControlBlock newProc = null;
        for(int i = 0; i < m_processes.size(); i++)
        {
            newProc = m_processes.get((i + offset) % m_processes.size());
            if ( ! newProc.isBlocked())
            {
                return newProc;
            }
        }//for

        return null;        // no processes are Ready
    }//getRandomProcess
    
    
    /**
     * aVietKyleScheduler
     * 
     * Process scheduling algorithm.
     * 
     * Processes have a priority in the range of 0..100, with 100 being the
     * highest priority. Priorities are based on number of times the process
     * has been in the ready queue. If a process waits longer than the
     * defined max starve time, it automatically receives highest priority.
     * 
     * @return highest priority process or null if there are no ready processes
     */
    ProcessControlBlock aVietKyleScheduler()
    {    	
        //Update priorities of all non-blocked processes and add to ready queue
        m_readyQueue.clear();
    	for (ProcessControlBlock pcb : m_processes)
    	{
    		if (!pcb.isBlocked())
    		{
    		    //are we starving?
    		    if (m_CPU.getTicks() - pcb.lastReadyTime > MAX_STARVE_TIME)
    		    {
    		        pcb.setPriority(100);
    		    }
    		    else
    		    {
    		        pcb.setPriority(pcb.numReady % 100);
    		    }
    		    
    		    //add to priority queue
                m_readyQueue.offer(pcb);
    		}
    	}//for	    	
    	
    	return m_readyQueue.peek();
    	
    }//aVietKyleScheduler
    
    /**
     * scheduleNewProcess
     * 
     * Selects an appropriate new process to run
     * 
     */
    public void scheduleNewProcess()
    {        
    	//if there are no processes left to run, exit
    	if(m_processes.size() == 0)
    	{
    		System.exit(0);
    	}
    	
    	//find next process to run
    	ProcessControlBlock nextUp = aVietKyleScheduler();
    	
    	if (nextUp != null)
    	{
    	    //switch to a higher priority process
    	    if(nextUp != m_currProcess)
    	    {
    	        if (m_currProcess != null) m_currProcess.save(m_CPU);
    	        m_currProcess = nextUp;
    	        m_currProcess.restore(m_CPU);
    	    }
    	}
    	else
    	{
    	    createIdleProcess();
    	}

    }//scheduleNewProcess
    

    /**
     * createIdleProcess
     *
     * creates a one instruction process that immediately exits.  This is used
     * to buy time until device I/O completes and unblocks a legitimate
     * process.
     *
     */
    public void createIdleProcess()
    {
        int progArr[] = { 0, 0, 0, 0,   //SET r0=0
                          0, 0, 0, 0,   //SET r0=0 (repeated instruction to account for vagaries in student implementation of the CPU class)
                         10, 0, 0, 0,   //PUSH r0
                         15, 0, 0, 0 }; //TRAP

        int allocSize = forceMultipleOfPageSize(progArr.length);
        
        //Initialize the starting position for this program
        int baseAddr = allocBlock(allocSize);
        
        //if alloc block fails, end simulation
        if (baseAddr == -1) {
        	System.out.println("Failed to load idle process");
        	System.exit(0);
        }

        //Load the program into RAM
        for(int i = 0; i < progArr.length; i++)
        {
            m_MMU.write(baseAddr + i, progArr[i]);
        }

        //Save the register info from the current process (if there is one)
        if (m_currProcess != null)
        {
            m_currProcess.save(m_CPU);
        }
        
        //Set the appropriate registers
        m_CPU.setPC(baseAddr);
        m_CPU.setSP(baseAddr + progArr.length + 10);
        m_CPU.setBASE(baseAddr);
        m_CPU.setLIM(baseAddr + progArr.length + 20);

        //Save the relevant info as a new entry in m_processes
        m_currProcess = new ProcessControlBlock(IDLE_PROC_ID);  
        m_processes.add(m_currProcess);

    }//createIdleProcess
    

    /*
     * ======================================================================
     * Program Management Methods
     * ----------------------------------------------------------------------
     */
    
    /**
     * addProgram
     *
     * registers a new program with the simulated OS that can be used when the
     * current process makes an Exec system call.  (Normally the program is
     * specified by the process via a filename but this is a simulation so the
     * calling process doesn't actually care what program gets loaded.)
     *
     * @param prog  the program to add
     *
     */
    public void addProgram(Program prog)
    {
        m_programs.add(prog);
    }//addProgram
    

    /**
     * createProcess
     * 
     * loads a program into RAM
     * 
     * @param prog
     *            the program to load into memory
     * @param allocSize
     *            the size allocated to the program in memory
     */
    public void createProcess(Program prog, int allocSize)
    {
    	
    	allocSize = forceMultipleOfPageSize(allocSize);
    	
    	m_programLoaded = false;
    	//find where to load the program in RAM
    	int nextLoadPos = allocBlock(allocSize);
    	
    	//check if there was enough space
    	if (nextLoadPos == -1) {
    		printPageTable();
    		return;
    	}
    	
    	// if there is a current process then store its register
    	// values onto the stack
    	if (m_currProcess != null) 
    	{
    		m_currProcess.save(m_CPU);
    	}  	    	
    	
    	m_currProcess = new ProcessControlBlock(m_nextProcessID);
    	m_nextProcessID++;
    	m_processes.add(m_currProcess);   	
    	    	
        // export the program and set necessary values in the CPU
        int[] programInstructions = new int[prog.getSize()];
        programInstructions = prog.export();
        
        m_CPU.setBASE(nextLoadPos);
        //make nextLoadPos 1 more than the end of the current program
        m_CPU.setLIM(m_CPU.getBASE() + allocSize);
        m_CPU.setPC(m_CPU.getBASE());
        m_CPU.setSP(m_CPU.getLIM() - 1);

        // move through the allocated memory and load the program instructions
        // into RAM,
        // one at a time, breaking if we go past the memory limit
        for (int i = 0; i < programInstructions.length; i++)
        {
            if (i > m_CPU.getLIM())
            {
                break;
            }
            m_MMU.write(m_CPU.getBASE() + i, programInstructions[i]);
        }
        
        m_currProcess.save(m_CPU);
        printMemAlloc();
        m_programLoaded = true;

    }// createProcess
    

    /**
     * pop
     * 
     * pops top value of off the stack
     * 
     * @return 0 if the stack is empty; else return the value on top of stack
     */
    private int pop()
    {
        if (m_CPU.getSP() < m_CPU.getLIM() - 1)
        {
            m_CPU.setSP(m_CPU.getSP() + 1);
            return m_MMU.read(m_CPU.getSP());
        }
        else
        {
            System.out.println("ERROR: THIS STACK IS EMPTY");
            System.exit(1);
            return 0;
        }
    }

    /**
     * push
     * 
     * pushes the value in the specified register on the stack
     * 
     * @param value
     *            the value to put on the stack
     * @return false if the stack is full, else true
     */
    private boolean push(int value)
    {
        if (m_CPU.getSP() >= m_CPU.getBASE())
        {
            m_MMU.write(m_CPU.getSP(), value);
            m_CPU.setSP(m_CPU.getSP() - 1);
            return true;
        }
        System.out.println("ERROR: STACK IS FULL");
        return false;
    }
    
    
    /*======================================================================
     * Virtual Memory Methods
     *----------------------------------------------------------------------
     */

    /**
     * initPageTable
     * 
     * Initializes the page table at the bottom of RAM.
     * After a call to initPageTable, each page maps directly to the
     * corresponding page.
     *  
     */
    private void initPageTable()
    {
    	int numPages = m_MMU.getNumPages();
    	int numFrames = m_MMU.getNumFrames();
    	
    	for (int i = 0; i < numPages; i++)
    	{
    		//map each page to the corresponding frame
    		if (i < numFrames)
    		{
    			m_RAM.write(i, i);
    		}
    		else
    		{
    			// -1 means that page is not currently loaded in RAM
    			m_RAM.write(i, -1);
    		}
    	}    	
    	
    }//initPageTable


    /**
     * printPageTable      *DEBUGGING*
     *
     * prints the page table in a human readable format
     *
     */
    private void printPageTable()
    {
        //If verbose mode is off, do nothing
        if (!m_verbose) return;

        //Print a header
        System.out.println("\n----------========== Page Table ==========----------");
        
        for(int i = 0; i < m_MMU.getNumPages(); i++)
        {
            int entry = m_MMU.read(i);
            int status = entry & m_MMU.getStatusMask();
            int frame = entry & m_MMU.getPageMask();

            System.out.println("" + i + "-->" + frame);
        }
        
        //Print a footer
        System.out.println("-----------------------------------------------------------------");

    }//printPageTable

    // Method used by SOS for system calls: depending on what the value of
    // SYSCALL_ID is, will call a helper method that corresponds to
    // that value
    public void systemCall()
    {
        
        int syscallId = pop();
        switch (syscallId)
        {
        case SYSCALL_EXIT:
            syscallExit();
            break;
        case SYSCALL_OUTPUT:
            syscallOutput();
            break;
        case SYSCALL_GETPID:
            syscallPID();
            break;
        case SYSCALL_COREDUMP:
            syscallDump();
            break;
        case SYSCALL_OPEN:
            syscallOpen();
            break;
        case SYSCALL_CLOSE:
            syscallClose();
            break;
        case SYSCALL_READ:
            syscallRead();
            break;
        case SYSCALL_WRITE:
            syscallWrite();
            break;
        case SYSCALL_EXEC:
            syscallExec();
            break;
        case SYSCALL_YIELD:
            syscallYield();
            break;
        }

    }

    /*
     * ======================================================================
     * Interrupt Handlers
     * ----------------------------------------------------------------------
     */

    /**
     * interruptIllegalMemoryAccess
     * 
     * Called when a process attempts to access memory outside its allocated
     * space. Prints an error and exits.
     * 
     * @param addr
     *            the address that was attempted to be accessed
     */
    @Override
    public void interruptIllegalMemoryAccess(int addr)
    {
        System.out.println("Illegal memory access at: " + addr);
        System.exit(0);
    }

    /**
     * interruptDivideByZero
     * 
     * Called when a process attempts to divide by zero. Prints an error and
     * exits.
     */
    @Override
    public void interruptDivideByZero()
    {
        System.out.println("Cannot divide by zero");
        System.exit(0);
    }

    /**
     * interruptIllegalInstruction
     * 
     * Called when a process attempts to execute an illegal instruction. Prints
     * an error and exits.
     * 
     * @param instr
     *            the illegal instruction that triggered the interrupt
     */
    @Override
    public void interruptIllegalInstruction(int[] instr)
    {
        System.out.println("Illegal instruction given: " + instr);
        System.exit(0);
    }
    
    /**
     * interruptIOReadComplete
     * 
     * A process is done waiting to read from a device.
     * 
     * @param devID the device ID
     * @param addr the address
     * @param data the data
     */
    @Override
    public void interruptIOReadComplete(int devID, int addr, int data)
    {
        for (DeviceInfo di : m_devices)
        {
            if(di.getId() == devID)
            {
                Device deviceDone = di.getDevice();
                
                for (ProcessControlBlock pcb : m_processes)
                {
                    //move the process from Waiting to Ready
                    if(pcb.isBlockedForDevice(deviceDone, SYSCALL_READ, addr))
                    {
                        pcb.unblock();                      
                        processPush(pcb, data);
                        processPush(pcb, SUCCESS);
                        return;
                    }
                }//for                
                
                //process not found
                
            }
        }//for
        
        //device not found
    }

    /**
     * interruptIOWriteComplete
     * 
     * A process is done waiting to write to a device.
     * 
     * @param devID the device ID
     * @param addr the address
     */
    @Override
    public void interruptIOWriteComplete(int devID, int addr)
    {
        for (DeviceInfo di : m_devices)
        {
            if(di.getId() == devID)
            {
                Device deviceDone = di.getDevice();
                
                for (ProcessControlBlock pcb : m_processes)
                {
                    //move the process from Waiting to Ready
                    if(pcb.isBlockedForDevice(deviceDone, SYSCALL_WRITE, addr))
                    {
                        pcb.unblock();                      
                        processPush(pcb, SUCCESS);
                        return;
                    }
                }//for                
                
                //process not found
                
            }
        }//for
        
        //device not found
        
    }
    
    /**
     * interruptClock
     * 
     * Interrupts process at the end of a time quantum
     */
    @Override
	public void interruptClock()
    {
		scheduleNewProcess();		
	}
    
    
    
    
    /**
     * processPush
     * 
     * Helper method to push a value onto a given process' stack
     * 
     * @param data
     * @return true if the value was pushed, false otherwise
     */
    private boolean processPush(ProcessControlBlock pcb, int data)
    {
        int processSP = pcb.getRegisterValue(CPU.SP);
        int processBASE = pcb.getRegisterValue(CPU.BASE);
        
        if (processSP >= processBASE)
        {
            m_MMU.write(processSP, data);
            pcb.setRegisterValue(CPU.SP, processSP - 1);
            return true;
        }
        System.out.println("ERROR: STACK IS FULL");
        return false;
    }


    /*
     * ======================================================================
     * System Calls
     * ----------------------------------------------------------------------
     */
    
    
    /**
     * syscallExec
     *
     * creates a new process.  The program used to create that process is chosen
     * semi-randomly from all the programs that have been registered with the OS
     * via {@link #addProgram}.  Limits are put into place to ensure that each
     * process is run an equal number of times.  If no programs have been
     * registered then the simulation is aborted with a fatal error.
     *
     */
    private void syscallExec()
    {
        //If there is nothing to run, abort.  This should never happen.
        if (m_programs.size() == 0)
        {
            System.err.println("ERROR!  syscallExec has no programs to run.");
            System.exit(-1);
        }
        
        //find out which program has been called the least and record how many
        //times it has been called
        int leastCallCount = m_programs.get(0).callCount;
        for(Program prog : m_programs)
        {
            if (prog.callCount < leastCallCount)
            {
                leastCallCount = prog.callCount;
            }
        }

        //Create a vector of all programs that have been called the least number
        //of times
        Vector<Program> cands = new Vector<Program>();
        for(Program prog : m_programs)
        {
            cands.add(prog);
        }
        
        //Select a random program from the candidates list
        Random rand = new Random();
        int pn = rand.nextInt(m_programs.size());
        Program prog = cands.get(pn);

        //Determine the address space size using the default if available.
        //Otherwise, use a multiple of the program size.
        int allocSize = prog.getDefaultAllocSize();
        if (allocSize <= 0)
        {
            allocSize = prog.getSize() * 2;
        }

        //Load the program into RAM
        createProcess(prog, allocSize);

        if(m_programLoaded == true)
        {
        	//Adjust the PC since it's about to be incremented by the CPU
        	m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);
        }

    }//syscallExec


    /**
     * syscallYield
     * 
     * Called when a process wants to move from the Running to the Ready state
     * 
     */
    private void syscallYield()
    {
        scheduleNewProcess();
    }//syscallYield

    /**
     * syscallExit
     * 
     * Called when handling a SYSCALL_EXIT.
     */
    private void syscallExit()
    {
        removeCurrentProcess();        
    }

    /**
     * syscallOutput
     * 
     * Called when handling a SYSCALL_OUTPUT. Pops the top value off of the
     * process's stack and prints it to console.
     */
    private void syscallOutput()
    {
        System.out.println("OUTPUT: " + pop());
    }

    /**
     * syscallPID
     * 
     * Called when handling a SYSCALL_GETPID. Pushes the current process's ID
     * to its stack.
     */
    private void syscallPID()
    {
        push(m_currProcess.getProcessId());
    }

    /**
     * syscallDump
     * 
     * Called when handling a SYSCALL_COREDUMP. Prints the contents of the
     * registers and top three values on the stack, then exits.
     */
    private void syscallDump()
    {
        System.out.println("CORE DUMPING:");
        m_CPU.regDump();
        System.out.println(pop() + "\n" + pop() + "\n" + pop());
        syscallExit();
    }

    /**
     * syscallOpen
     * 
     * Pops a device ID off the stack, then adds the current process to that
     * device.
     */
    private void syscallOpen()
    {
        int devId = pop();
        
        for (DeviceInfo deviceInfo : m_devices)
        {
            if (deviceInfo.getId() == devId)
            {
                if (!deviceInfo.getDevice().isSharable()
                        && !deviceInfo.unused())
                {
                    // Device cannot be opened at this time, so the process must wait
                	deviceInfo.addProcess(m_currProcess);
                	m_currProcess.block(m_CPU, deviceInfo.getDevice(), SYSCALL_OPEN, -1);
                	scheduleNewProcess();
                    return;
                }
                else if (deviceInfo.containsProcess(m_currProcess))
                {
                    // The process has already opened this device
                    push(DEVICE_ALREADY_OPEN);
                    return;
                }
                else
                {
                    deviceInfo.addProcess(m_currProcess);
                    push(SUCCESS);
                    return;
                }
            }
        }
        // If we're here, the device doesn't exist
        push(DEVICE_NOT_FOUND);
    }

    /**
     * syscallClose
     * 
     * Pops a device ID off the stack, then removes the current process from
     * that device.
     */
    private void syscallClose()
    {
        int devId = pop();
        
        for (DeviceInfo deviceInfo : m_devices)
        {
            if (deviceInfo.getId() == devId)
            {
                if (!deviceInfo.containsProcess(m_currProcess))
                {
                    // The process has not opened this device
                    push(DEVICE_NOT_OPEN);
                    return;
                }
                deviceInfo.removeProcess(m_currProcess);
                push(SUCCESS);
                
                //if another process wants to open the device, unblock it
                ProcessControlBlock nextProcess = selectBlockedProcess(deviceInfo.getDevice(), SYSCALL_OPEN, -1);
                if(nextProcess != null) {
                    nextProcess.unblock();
                    processPush(nextProcess, SUCCESS);
                }
                
                return;
            }
        }
        // If we're here, the device doesn't exist
        push(DEVICE_NOT_FOUND);
    }

    /**
     * syscallRead
     * 
     * Pops an address and device ID from the stack. Then reads from the given
     * address on the specified device, pushing the result to the stack.
     */
    private void syscallRead()
    {
        int addr = pop();
        int devId = pop();

        for (DeviceInfo deviceInfo : m_devices)
        {
            if (deviceInfo.getId() == devId)
            {
                Device device = deviceInfo.getDevice();
                if (!deviceInfo.containsProcess(m_currProcess))
                {
                    // The process has not opened this device
                    push(DEVICE_NOT_OPEN);
                    return;
                }
                else if (!device.isReadable())
                {
                    // Device is write-only
                    push(DEVICE_WRITE_ONLY);
                    return;
                }                
                
                //issue read command, if device is available
                if (device.isAvailable())
                {
                    device.read(addr);
                    //process must now wait for results
                    m_currProcess.block(m_CPU, device, SYSCALL_READ, addr);
                    scheduleNewProcess();
                    return;
                }
                else
                {
                    //process must wait for the device
                    
                    //decrement PC to ensure TRAP is re-executed
                    m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);
                    
                    //push values back so we can try again
                    push(devId);
                    push(addr);
                    push(SYSCALL_READ);
                    
                    scheduleNewProcess();
                    return;
                }
                
                
            }
        }
        // If we're here, the device doesn't exist
        push(DEVICE_NOT_FOUND);
    }

    /**
     * syscallWrite
     * 
     * Pops the value, address, and device ID from the stack. Then writes the
     * given data to the specified device.
     */
    private void syscallWrite()
    {
        int value = pop();
        int addr = pop();
        int devId = pop();

        for (DeviceInfo deviceInfo : m_devices)
        {
            if (deviceInfo.getId() == devId)
            {
                Device device = deviceInfo.getDevice();
                if (!deviceInfo.containsProcess(m_currProcess))
                {
                    // The process has not opened this device
                    push(DEVICE_NOT_OPEN);
                    return;
                }
                else if (!device.isWriteable())
                {
                    // Device is read-only
                    push(DEVICE_READ_ONLY);
                    return;
                }
                
                //issue write command, if device is available
                if (device.isAvailable())
                {
                    device.write(addr, value);
                    //process must now wait for results
                    m_currProcess.block(m_CPU, device, SYSCALL_WRITE, addr);
                    scheduleNewProcess();
                    return;
                }
                else
                {
                    //process must wait for the device                    
                    
                    //decrement PC to ensure TRAP is re-executed
                    m_CPU.setPC(m_CPU.getPC() - CPU.INSTRSIZE);
                    
                    //push the values back so we can try again
                    push(devId);
                    push(addr);
                    push(value);
                    push(SYSCALL_WRITE);
                    
                    scheduleNewProcess();
                    return;
                }
                
                
            }
        }
        // If we're here, the device doesn't exist
        push(DEVICE_NOT_FOUND);
    }    
    
    /**
     * selectBlockedProcess
     *
     * select a process to unblock that might be waiting to perform a given
     * action on a given device.  This is a helper method for system calls
     * and interrupts that deal with devices.
     *
     * @param dev   the Device that the process must be waiting for
     * @param op    the operation that the process wants to perform on the
     *              device.  Use the SYSCALL constants for this value.
     * @param addr  the address the process is reading from.  If the
     *              operation is a Write or Open then this value can be
     *              anything
     *
     * @return the process to unblock -OR- null if none match the given criteria
     */
    public ProcessControlBlock selectBlockedProcess(Device dev, int op, int addr)
    {
        ProcessControlBlock selected = null;
        for(ProcessControlBlock pi : m_processes)
        {
            if (pi.isBlockedForDevice(dev, op, addr))
            {
                selected = pi;
                break;
            }
        }//for

        return selected;
    }//selectBlockedProcess
    
    

    /*
     * ======================================================================
     * Device Management Methods
     * ----------------------------------------------------------------------
     */

    /**
     * registerDevice
     * 
     * adds a new device to the list of devices managed by the OS
     * 
     * @param dev
     *            the device driver
     * @param id
     *            the id to assign to this device
     * 
     */
    public void registerDevice(Device dev, int id)
    {
        m_devices.add(new DeviceInfo(dev, id));
    }// registerDevice

    //======================================================================
    // Inner Classes
    //----------------------------------------------------------------------

    /**
     * class MemBlock
     *
     * This class contains relevant info about a memory block in RAM.
     *
     */
    private class MemBlock implements Comparable<MemBlock>
    {
        /** the address of the block */
        private int m_addr;
        /** the size of the block */
        private int m_size;

        /**
         * ctor does nothing special
         */
        public MemBlock(int addr, int size)
        {
            m_addr = addr;
            m_size = size;
        }

        /** accessor methods */
        public int getAddr() { return m_addr; }
        public int getSize() { return m_size; }
        
        /**
         * compareTo              
         *
         * compares this to another MemBlock object based on address
         */
        public int compareTo(MemBlock m)
        {
            return this.m_addr - m.m_addr;
        }

    }//class MemBlock
    
    
    /**
     * class ProcessControlBlock
     * 
     * This class contains information about a currently active process.
     */
    private class ProcessControlBlock implements Comparable<ProcessControlBlock>
    {
        /**
         * a unique id for this process
         */
        private int processId = 0;
        
        /**
         * priority of this process
         */
        private int priority = 0;
        
        /**
         * These are the process' current registers.  If the process is in the
         * "running" state then these are out of date
         */
        private int[] registers = null;

        /**
         * If this process is blocked a reference to the Device is stored here
         */
        private Device blockedForDevice = null;
        
        /**
         * If this process is blocked a reference to the type of I/O operation
         * is stored here (use the SYSCALL constants defined in SOS)
         */
        private int blockedForOperation = -1;
        
        /**
         * If this process is blocked reading from a device, the requested
         * address is stored here.
         */
        private int blockedForAddr = -1;
        
        /**
         * the time it takes to load and save registers, specified as a number
         * of CPU ticks
         */
        private static final int SAVE_LOAD_TIME = 30;
        
        /**
         * Used to store the system time when a process is moved to the Ready
         * state.
         */
        private int lastReadyTime = -1;
        
        /**
         * Used to store the number of times this process has been in the ready
         * state
         */
        private int numReady = 0;
        
        /**
         * Used to store the maximum starve time experienced by this process
         */
        private int maxStarve = -1;
        
        /**
         * Used to store the average starve time for this process
         */
        private double avgStarve = 0;
        

        /**
         * constructor
         * 
         * @param pid
         *            a process id for the process. The caller is responsible
         *            for making sure it is unique.
         */
        public ProcessControlBlock(int pid)
        {
            this.processId = pid;
        }

        /**
         * @return the current process' id
         */
        public int getProcessId()
        {
            return this.processId;
        }
        
        /**
         * @return the current process' priority
         */
        public int getPriority()
        {
        	return priority;
        }
        
        /**
         * @return the last time this process was put in the Ready state
         */
        public long getLastReadyTime()
        {
            return lastReadyTime;
        }
        
        /**
         * save
         *
         * saves the current CPU registers into this.registers
         *
         * @param cpu  the CPU object to save the values from
         */
        public void save(CPU cpu)
        {
            //A context switch is expensive.  We simluate that here by 
            //adding ticks to m_CPU
            m_CPU.addTicks(SAVE_LOAD_TIME);
            
            //Save the registers
            int[] regs = cpu.getRegisters();
            this.registers = new int[CPU.NUMREG];
            for(int i = 0; i < CPU.NUMREG; i++)
            {
                this.registers[i] = regs[i];
            }

            //Assuming this method is being called because the process is moving
            //out of the Running state, record the current system time for
            //calculating starve times for this process.  If this method is
            //being called for a Block, we'll adjust lastReadyTime in the
            //unblock method.
            numReady++;
            lastReadyTime = m_CPU.getTicks();
            
        }//save
         
        /**
         * restore
         *
         * restores the saved values in this.registers to the current CPU's
         * registers
         *
         * @param cpu  the CPU object to restore the values to
         */
        public void restore(CPU cpu)
        {
            //A context switch is expensive.  We simluate that here by 
            //adding ticks to m_CPU
            m_CPU.addTicks(SAVE_LOAD_TIME);
            
            //Restore the register values
            int[] regs = cpu.getRegisters();
            for(int i = 0; i < CPU.NUMREG; i++)
            {
                regs[i] = this.registers[i];
            }

            //Record the starve time statistics
            int starveTime = m_CPU.getTicks() - lastReadyTime;
            if (starveTime > maxStarve)
            {
                maxStarve = starveTime;
            }
            double d_numReady = (double)numReady;
            avgStarve = avgStarve * (d_numReady - 1.0) / d_numReady;
            avgStarve = avgStarve + (starveTime * (1.0 / d_numReady));
        }//restore
         
        /**
         * block
         *
         * blocks the current process to wait for I/O.  This includes saving the
         * process' registers.   The caller is responsible for calling
         * {@link CPU#scheduleNewProcess} after calling this method.
         *
         * @param cpu   the CPU that the process is running on
         * @param dev   the Device that the process must wait for
         * @param op    the operation that the process is performing on the
         *              device.  Use the SYSCALL constants for this value.
         * @param addr  the address the process is reading from.  If the
         *              operation is a Write or Open then this value can be
         *              anything
         */
        public void block(CPU cpu, Device dev, int op, int addr)
        {
            blockedForDevice = dev;
            blockedForOperation = op;
            blockedForAddr = addr;
            
        }//block
        
        /**
         * unblock
         *
         * moves this process from the Blocked (waiting) state to the Ready
         * state. 
         *
         */
        public void unblock()
        {
            //Reset the info about the block
            blockedForDevice = null;
            blockedForOperation = -1;
            blockedForAddr = -1;
            
            //Assuming this method is being called because the process is moving
            //from the Blocked state to the Ready state, record the current
            //system time for calculating starve times for this process.
            lastReadyTime = m_CPU.getTicks();
            
        }//unblock
        
        /**
         * isBlocked
         *
         * @return true if the process is blocked
         */
        public boolean isBlocked()
        {
            return (blockedForDevice != null);
        }//isBlocked
         
        /**
         * isBlockedForDevice
         *
         * Checks to see if the process is blocked for the given device,
         * operation and address.  If the operation is not an open, the given
         * address is ignored.
         *
         * @param dev   check to see if the process is waiting for this device
         * @param op    check to see if the process is waiting for this operation
         * @param addr  check to see if the process is reading from this address
         *
         * @return true if the process is blocked by the given parameters
         */
        public boolean isBlockedForDevice(Device dev, int op, int addr)
        {
            if ( (blockedForDevice == dev) && (blockedForOperation == op) )
            {
                if (op == SYSCALL_OPEN)
                {
                    return true;
                }

                if (addr == blockedForAddr)
                {
                    return true;
                }
            }//if

            return false;
        }//isBlockedForDevice
         
        
        /**
         * compareTo              
         *
         * compares this to another ProcessControlBlock object based on the BASE addr
         * register.  Read about Java's Collections class for info on
         * how this method can be quite useful to you.
         */
        public int compareTo(ProcessControlBlock pi)
        {
            return this.registers[CPU.BASE] - pi.registers[CPU.BASE];
        }
        
        /**
         * getRegisterValue
         *
         * Retrieves the value of a process' register that is stored in this
         * object (this.registers).
         * 
         * @param idx the index of the register to retrieve.  Use the constants
         *            in the CPU class
         * @return one of the register values stored in in this object or -999
         *         if an invalid index is given 
         */
        public int getRegisterValue(int idx)
        {
            if ((idx < 0) || (idx >= CPU.NUMREG))
            {
                return -999;    // invalid index
            }
            
            return this.registers[idx];
        }//getRegisterValue
         
        /**
         * setRegisterValue
         *
         * Sets the value of a process' register that is stored in this
         * object (this.registers).  
         * 
         * @param idx the index of the register to set.  Use the constants
         *            in the CPU class.  If an invalid index is given, this
         *            method does nothing.
         * @param val the value to set the register to
         */
        public void setRegisterValue(int idx, int val)
        {
            if ((idx < 0) || (idx >= CPU.NUMREG))
            {
                return;    // invalid index
            }
            
            this.registers[idx] = val;
        }//setRegisterValue
         
    

        /**
         * overallAvgStarve
         *
         * @return the overall average starve time for all currently running
         *         processes
         *
         */
        public double overallAvgStarve()
        {
            double result = 0.0;
            int count = 0;
            for(ProcessControlBlock pi : m_processes)
            {
                if (pi.avgStarve > 0)
                {
                    result = result + pi.avgStarve;
                    count++;
                }
            }
            if (count > 0)
            {
                result = result / count;
            }
            
            return result;
        }//overallAvgStarve
        
        /**
         * addPriority
         * 
         * Set the priority of this process
         * 
         * @param amount integer between 0..100
         */
        public void setPriority(int amount)
        {
        	priority = amount;
        }
        
        /**
         * toString       **DEBUGGING**
         *
         * @return a string representation of this class
         */
        public String toString()
        {
            //Print the Process ID and process state (READY, RUNNING, BLOCKED)
            String result = "Process id " + processId + " ";
            if (isBlocked())
            {
                result = result + "is BLOCKED for ";
                //Print device, syscall and address that caused the BLOCKED state
                if (blockedForOperation == SYSCALL_OPEN)
                {
                    result = result + "OPEN";
                }
                else
                {
                    result = result + "WRITE @" + blockedForAddr;
                }
                for(DeviceInfo di : m_devices)
                {
                    if (di.getDevice() == blockedForDevice)
                    {
                        result = result + " on device #" + di.getId();
                        break;
                    }
                }
                result = result + ": ";
            }
            else if (this == m_currProcess)
            {
                result = result + "is RUNNING: ";
            }
            else
            {
                result = result + "is READY: ";
            }

            //Print the register values stored in this object.  These don't
            //necessarily match what's on the CPU for a Running process.
            if (registers == null)
            {
                result = result + "<never saved>";
                return result;
            }
            
            for(int i = 0; i < CPU.NUMGENREG; i++)
            {
                result = result + ("r" + i + "=" + registers[i] + " ");
            }//for
            result = result + ("PC=" + registers[CPU.PC] + " ");
            result = result + ("SP=" + registers[CPU.SP] + " ");
            result = result + ("BASE=" + registers[CPU.BASE] + " ");
            result = result + ("LIM=" + registers[CPU.LIM] + " ");

            //Print the starve time statistics for this process
            result = result + "\n\t\t\t";
            result = result + " Max Starve Time: " + maxStarve;
            result = result + " Avg Starve Time: " + avgStarve;
        
            return result;
        }//toString
        
        
        /**
         * move
         * 
         * Attempts to move a process to a different block in RAM
         * This move only moves process down in RAM
         * 
         * @param newBase address of new block
         * @return true if move was successful
         */
        public boolean move(int newBase)
        {    		        	
    		//check to see if it is the current running process
        	boolean isCurrent = false;
        	if (m_currProcess != null)
        	{
	        	if(compareTo(m_currProcess) == 0)
	        	{
	        		isCurrent = true;
	        		save(m_CPU);
	        	}        	    
        	}
            
            //get the page number of:
        	//the page the process is moving to:
            int newPageNum = newBase & m_MMU.getPageMask();
            newPageNum = newPageNum >> m_MMU.getOffsetSize();
            
            //the page the process currently starts on:
            int currBase = getRegisterValue(CPU.BASE);
            int currStartPageNum = currBase & m_MMU.getPageMask();
            currStartPageNum = currStartPageNum >> m_MMU.getOffsetSize();
    		
    		int howManyPages = (getRegisterValue(CPU.LIM) - currBase) / m_MMU.getPageSize();
            
    		//swap entries in page table to move the process
        	for (int i = 0; i < howManyPages; i++)
        	{
        		int targetEntry = m_RAM.read(newPageNum + i);
        		int originalEntry = m_RAM.read(currStartPageNum + i);
        		
        		m_RAM.write(currStartPageNum + i, targetEntry);
        		m_RAM.write(newPageNum + i, originalEntry);
        	}
            
        	debugPrintln("Process " + getProcessId() + " has moved from " + getRegisterValue(CPU.BASE) + " to " + newBase + ".");
        	
        	//set the new register values, effectively switching pages
        	int newPC = getRegisterValue(CPU.PC) - getRegisterValue(CPU.BASE) + newBase;
        	int newSP = getRegisterValue(CPU.SP) - getRegisterValue(CPU.BASE) + newBase;
        	int newLim = getRegisterValue(CPU.LIM) - getRegisterValue(CPU.BASE) + newBase;
       	
        	setRegisterValue(CPU.BASE, newBase);
        	setRegisterValue(CPU.LIM, newLim);
        	setRegisterValue(CPU.PC, newPC);
        	setRegisterValue(CPU.SP, newSP);
        	
        	//if it was the current running process update CPU registers
        	if(isCurrent) restore(m_CPU);
    		
        	return true;
        	
        }//move


    }// class ProcessControlBlock

    /**
     * class DeviceInfo
     * 
     * This class contains information about a device that is currently
     * registered with the system.
     */
    private class DeviceInfo
    {
        /** every device has a unique id */
        private int id;
        /** a reference to the device driver for this device */
        private Device device;
        /** a list of processes that have opened this device */
        private Vector<ProcessControlBlock> procs;

        /**
         * constructor
         * 
         * @param d
         *            a reference to the device driver for this device
         * @param initID
         *            the id for this device. The caller is responsible for
         *            guaranteeing that this is a unique id.
         */
        public DeviceInfo(Device d, int initID)
        {
            this.id = initID;
            this.device = d;
            this.procs = new Vector<ProcessControlBlock>();
        }

        /** @return the device's id */
        public int getId()
        {
            return this.id;
        }

        /** @return this device's driver */
        public Device getDevice()
        {
            return this.device;
        }

        /** Register a new process as having opened this device */
        public void addProcess(ProcessControlBlock pi)
        {
            procs.add(pi);
        }

        /** Register a process as having closed this device */
        public void removeProcess(ProcessControlBlock pi)
        {
            procs.remove(pi);
        }

        /** Does the given process currently have this device opened? */
        public boolean containsProcess(ProcessControlBlock pi)
        {
            return procs.contains(pi);
        }

        /** Is this device currently not opened by any process? */
        public boolean unused()
        {
            return procs.size() == 0;
        }

    }// class DeviceInfo
    
    /**
     * class MaxHeapifier
     * 
     * Comparator class used to create a max heap for process scheduling
     * 
     */
    public class MaxHeapifier implements Comparator<ProcessControlBlock>
    {
        /**
         * compare
         * 
         * Compares two processes based on priority
         * 
         * @return >0 if a is higher priority than b
         *         <0 if a is lower priority than b
         *          0 if a and b have the same priority
         */
        public int compare(ProcessControlBlock a, ProcessControlBlock b)
        {
            return a.getPriority() - b.getPriority();
        }
    }// class MaxHeapifier

		

};// class SOS
