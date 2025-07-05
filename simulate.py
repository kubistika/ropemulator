from unicorn import *
from unicorn.arm64_const import *
from capstone import *
from rich.console import Console
from rich.table import Table
from rich import box
import struct

# Console
console = Console()

# Memory layout
ADDRESS = 0x400000
STACK_ADDR = 0x700000
STACK_SIZE = 0x10000  # 64 KB
CODE_SIZE = 0x10000  # Increased to fit all gadgets

from pwn import *

context.arch = "arm64"  # Set architecture for pwntools
# Fake ROP gadgets (addresses and instructions)
gadgets = {}


def add_gadget(addr, code):
    instructions = code.split(" ; ")
    for instr in instructions:
        gadgets[addr] = asm(instr)
        addr += 4  # Increment address for each instruction


add_gadget(0x402000, "ldp x29, x30, [sp], #0x10 ; ret")
add_gadget(0x403000, "ldp x0, x1, [sp], #0x10 ; ret")
add_gadget(0x401000, "mov x0, #0x1337; ret")
add_gadget(0x401010, "mov x1, x0; ret")
add_gadget(0x401020, "svc #0")
add_gadget(0x404000, "ldp x0, x1, [sp, #0x10] ; ldp x29, x30, [sp], #0x10 ; ret")


def init_emulator(rop_chain):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    # Map memory
    mu.mem_map(ADDRESS, CODE_SIZE)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    # Write gadget code
    for addr, code in gadgets.items():
        mu.mem_write(addr, code)

    # Setup stack
    stack_top = STACK_ADDR + STACK_SIZE
    rop_size = len(rop_chain) * 8
    sp_start = stack_top - rop_size
    sp_start &= ~0x7  # 8-byte align

    # Write ROP chain to stack
    for i, val in enumerate(rop_chain):
        offset = sp_start + i * 8
        if not (STACK_ADDR <= offset < STACK_ADDR + STACK_SIZE):
            raise RuntimeError("ROP chain write out of stack bounds")
        mu.mem_write(offset, struct.pack("<Q", val))

    # Setup initial registers
    mu.reg_write(UC_ARM64_REG_PC, rop_chain[0])  # simulate return into first gadget
    mu.reg_write(UC_ARM64_REG_SP, sp_start + 8)

    return mu


# Disassembler
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def disas(addr):
    try:
        code = mu.mem_read(addr, 4)
        instrs = list(cs.disasm(code, addr))
        return f"{instrs[0].mnemonic} {instrs[0].op_str}" if instrs else "?"
    except:
        return "Invalid"


# Track previous register state
prev_regs = {}


def get_registers(mu):
    regs = {}
    for i in range(29):
        regs[f"x{i}"] = mu.reg_read(UC_ARM64_REG_X0 + i)
    regs["X29"] = mu.reg_read(UC_ARM64_REG_X29)
    regs["SP"] = mu.reg_read(UC_ARM64_REG_SP)
    regs["PC"] = mu.reg_read(UC_ARM64_REG_PC)
    regs["LR"] = mu.reg_read(UC_ARM64_REG_LR)
    return regs


def print_view(mu):
    global prev_regs
    current_regs = get_registers(mu)

    from rich.layout import Layout
    from rich.panel import Panel

    # Build register table (modern, visually appealing)
    reg_table = Table(
        show_header=True, box=box.SIMPLE_HEAVY, pad_edge=True, style="white on #23272e"
    )
    reg_table.add_column(
        "[bold cyan]x0-x9[/bold cyan]", style="bold white", justify="right"
    )
    reg_table.add_column(
        "[bold cyan]x10-x19[/bold cyan]", style="bold white", justify="right"
    )
    reg_table.add_column(
        "[bold cyan]x20-x28[/bold cyan]", style="bold white", justify="right"
    )
    reg_table.add_column(
        "[bold cyan]Extra[/bold cyan]", style="bold cyan", justify="right"
    )

    col1 = []
    col2 = []
    col3 = []
    for i in range(0, 10):
        name = f"x{i}"
        val = current_regs[name]
        prev = prev_regs.get(name)
        value_str = f"{val:#018x}"
        if prev is not None and prev != val:
            value_str = f"[bold red]{value_str}[/bold red]"
        col1.append(f"{name}: {value_str}")
    for i in range(10, 20):
        name = f"x{i}"
        val = current_regs[name]
        prev = prev_regs.get(name)
        value_str = f"{val:#018x}"
        if prev is not None and prev != val:
            value_str = f"[bold red]{value_str}[/bold red]"
        col2.append(f"{name}: {value_str}")
    for i in range(20, 29):
        name = f"x{i}"
        val = current_regs[name]
        prev = prev_regs.get(name)
        value_str = f"{val:#018x}"
        if prev is not None and prev != val:
            value_str = f"[bold red]{value_str}[/bold red]"
        col3.append(f"{name}: {value_str}")
    extra_regs = ["X29", "LR", "PC", "SP"]
    extra_col = []
    for name in extra_regs:
        val = current_regs[name]
        prev = prev_regs.get(name)
        value_str = f"{val:#018x}"
        if prev is not None and prev != val:
            value_str = f"[bold red]{value_str}[/bold red]"
        extra_col.append(f"{name}: {value_str}")
    max_rows = max(len(col1), len(col2), len(col3), len(extra_col))
    for i in range(max_rows):
        r1 = col1[i] if i < len(col1) else ""
        r2 = col2[i] if i < len(col2) else ""
        r3 = col3[i] if i < len(col3) else ""
        r4 = extra_col[i] if i < len(extra_col) else ""
        reg_table.add_row(r1, r2, r3, r4)

    # Build stack table (modern, visually appealing)
    sp_val = current_regs["SP"]
    stack_table = Table(
        show_header=True, box=box.SIMPLE_HEAVY, pad_edge=True, style="white on #23272e"
    )
    stack_table.add_column(
        "[bold magenta]Address[/bold magenta]", style="bold white", justify="right"
    )
    stack_table.add_column(
        "[bold magenta]Value[/bold magenta]", style="bold yellow", justify="left"
    )
    for i in range(-5, 10):
        addr = sp_val + i * 8
        is_sp = addr == sp_val
        if STACK_ADDR <= addr < STACK_ADDR + STACK_SIZE:
            val = struct.unpack("<Q", mu.mem_read(addr, 8))[0]
            val_str = f"{val:#018x}"
        else:
            val_str = "??"
        if is_sp:
            stack_table.add_row(
                f"[bold reverse yellow]{addr:#018x}[/bold reverse yellow]",
                f"[bold reverse yellow]{val_str}[/bold reverse yellow]",
            )
        else:
            stack_table.add_row(f"{addr:#018x}", val_str)

    pc = current_regs["PC"]
    print(f"Current PC: 0x{pc:x} {disas(pc)}")
    instr = disas(pc).replace("[", "\\[")

    # Layout: registers left, stack right, instruction bottom, all in boxes
    from rich.panel import Panel
    from rich import box as rich_box

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main", ratio=8),
        Layout(name="instr", size=4),
        Layout(name="footer", size=1),
    )
    layout["main"].split_row(
        Layout(
            Panel(
                reg_table,
                title="[b cyan]Registers[/b cyan]",
                border_style="bright_cyan",
                box=rich_box.DOUBLE,
                padding=(1, 4),
                style="on #1a1d23",
            ),
            name="registers",
            ratio=1,
        ),
        Layout(
            Panel(
                stack_table,
                title="[b magenta]Stack[/b magenta]",
                border_style="bright_magenta",
                box=rich_box.DOUBLE,
                padding=(1, 4),
                style="on #1a1d23",
            ),
            name="stack",
            ratio=1,
        ),
    )
    from rich.align import Align

    layout["header"].update(
        Align.center(
            Panel(
                "[b white on #23272e] ARM64 ROP Chain Visualizer ",
                box=rich_box.HEAVY,
                border_style="bright_cyan",
                padding=(0, 2),
            ),
            vertical="middle",
        )
    )
    layout["instr"].update(
        Align.center(
            Panel(
                f"[green bold]Executing:[/green bold] [b white]0x{pc:x}[/b white] → [b yellow]{instr}[/b yellow]",
                title="[b green]Current Instruction[/b green]",
                border_style="bright_green",
                box=rich_box.HEAVY,
                padding=(1, 4),
                style="on #23272e",
            ),
            vertical="middle",
        )
    )
    layout["footer"].update(
        Align.center(
            "[dim]Press Ctrl+C to exit.  |  [b cyan]github.com/kubistika/ropemulator[/b cyan]",
            vertical="middle",
        )
    )
    console.clear()
    console.print(layout, soft_wrap=True)

    # Save current state for diff
    prev_regs = current_regs.copy()


# Step-by-step execution hook
def hook_code(mu, address, size, user_data):
    print_view(mu)
    try:
        input()
    except KeyboardInterrupt:
        console.print("[bold red]Execution interrupted by user.[/bold red]")
        mu.emu_stop()


# Add hook and start
def run(mu):
    mu.hook_add(UC_HOOK_CODE, hook_code)

    try:
        mu.emu_start(mu.reg_read(UC_ARM64_REG_PC), ADDRESS + CODE_SIZE)
    except UcError as e:
        # Try to get the address that caused the exception
        err_addr = None
        try:
            err_addr = mu.reg_read(UC_ARM64_REG_PC)
        except Exception:
            pass
        if err_addr is not None:
            console.print(
                f"[bold red]Execution stopped:[/bold red] {e} at address 0x{err_addr:x}"
            )
        else:
            console.print(f"[bold red]Execution stopped:[/bold red] {e}")


rop_chain = [0x402000, 0x29, 0x404000, 0x29, 0x30, 0xAA, 0xBB]
mu = init_emulator(rop_chain)
run(mu)
