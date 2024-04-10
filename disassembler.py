import sys


source = b''
offset = 0

labels = dict()
loc = 0


# converts little-endian byte string to number
# Example: b'\x12\x00\x00\x00' --> 18
def convert(string):
    result = 0
    for i in range(len(string) - 1, -1, -1):
        result = 256 * result + string[i]
    return result


# reads the required number of bytes,
# convert it to number and shifts offset
def read(size):
    global source, offset

    if offset < 0 or offset + size > len(source):
        print(f'Cannot read byte at position {offset + size - 1}')
        print('The input file size is too small')
        sys.exit()

    offset += size
    return convert(source[offset - size:offset])


# reads the required number of bytes and convert it binary
# Example b'\x91\xc7Ue' --> '01100101010101011100011110010001'
def read_bin(size):
    return bin(read(size))[2:].rjust(8 * size, '0')


def read_elf():
    global source

    if len(sys.argv) < 3:
        print('Invalid number of arguments. Please enter:')
        print(sys.argv[0], '<input_filename> <output_filename>')
        sys.exit()

    try:
        input_file = open(sys.argv[1], 'rb')
        for line in input_file:
            source += line
        input_file.close()
    except FileNotFoundError:
        print(f'No such file or directory: {sys.argv[1]}')
        sys.exit()
    except IOError:
        print('Error while reading file')
        sys.exit()


def parse_header():
    eident_keys = [127, 69, 76, 70, 1, 1, 1]
    eident_values = [0] * 16

    for i in range(16):
        eident_values[i] = read(1)

    if eident_values[:7] != eident_keys:
        print('The file format is not supported')
        sys.exit()

    e_type = read(2)
    e_machine = read(2)
    e_version = read(4)
    e_entry = read(4)
    e_phoff = read(4)
    e_shoff = read(4)
    e_flags = read(4)
    e_ehsize = read(2)
    e_phentsize = read(2)
    e_phnum = read(2)
    e_shentsize = read(2)
    e_shnum = read(2)
    e_shstrndx = read(2)

    if e_type != 2 or e_machine != 243 or e_version != 1 or e_ehsize != 52 or e_phentsize != 32 or e_shentsize != 40:
        print('The file format is not supported')
        sys.exit()

    return e_shoff, e_shentsize, e_shnum, e_shstrndx


def parse_section_headers(e_shoff, e_shentsize, e_shnum, e_shstrndx):
    global source, offset

    sections = []
    section_header_variables = ['name', 'type', 'flags', 'addr', 'offset',
                                'size', 'link', 'info', 'addralign', 'entsize']

    for i in range(e_shnum):
        offset = e_shoff + i * e_shentsize
        sections.append(dict())
        for j in section_header_variables:
            sections[i][j] = read(4)

    shstrtab_header = sections[e_shstrndx]
    text_header = None
    symtab_header = None
    strtab_header = None

    if shstrtab_header['offset'] < 0 or shstrtab_header['offset'] + shstrtab_header['size'] > len(source):
        print(f'Cannot read byte at position {shstrtab_header["offset"] + shstrtab_header["size"] - 1}')
        print('The input file size is too small')
        sys.exit()
    shstrtab_section = source[shstrtab_header['offset']:shstrtab_header['offset'] + shstrtab_header['size']].decode('utf-8')

    for i in range(e_shnum):
        offset = sections[i]['name']
        sections[i]['name'] = ''
        while offset < len(shstrtab_section) and shstrtab_section[offset] != '\x00':
            sections[i]['name'] += shstrtab_section[offset]
            offset += 1

        if sections[i]['name'] == '.text':
            text_header = sections[i]
        elif sections[i]['name'] == '.symtab':
            symtab_header = sections[i]
        elif sections[i]['name'] == '.strtab':
            strtab_header = sections[i]

    if text_header is None:
        print('Cannot find .text section')
        sys.exit()
    if symtab_header is None:
        print('Cannot find .symtab section')
        sys.exit()
    if strtab_header is None:
        print('Cannot find .strtab section')
        sys.exit()

    return text_header, symtab_header, strtab_header


def parse_symtab(symtab_header, strtab_header):
    global source, offset, labels

    if strtab_header['offset'] < 0 or strtab_header['offset'] + strtab_header['size'] > len(source):
        print(f'Cannot read byte at position {strtab_header["offset"] + strtab_header["size"] - 1}')
        print('The input file size is too small')
        sys.exit()
    strtab_section = source[strtab_header['offset']:strtab_header['offset'] + strtab_header['size']].decode('utf-8')

    entries_number = symtab_header['size'] // symtab_header['entsize']
    offset = symtab_header['offset']

    symtab_section = []

    for i in range(entries_number):
        symtab_section.append(dict())
        symtab_section[i]['name'] = read(4)
        symtab_section[i]['value'] = read(4)
        symtab_section[i]['size'] = read(4)
        symtab_section[i]['info'] = read(1)
        symtab_section[i]['other'] = read(1)
        symtab_section[i]['shndx'] = read(2)

        j = symtab_section[i]['name']
        symtab_section[i]['name'] = ''
        while j < len(strtab_section) and strtab_section[j] != '\x00':
            symtab_section[i]['name'] += strtab_section[j]
            j += 1

        st_bind = {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK', 3: 'NUM',
                   10: 'LOOS', 12: 'HIOS', 13: 'LOPROC', 15: 'HIPROC'}
        symtab_section[i]['bind'] = st_bind[symtab_section[i]['info'] >> 4]

        st_type = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION',
                   4: 'FILE', 5: 'COMMON', 6: 'TLS', 7: 'NUM',
                   10: 'LOOS', 12: 'HIOS', 13: 'LOPROC', 15: 'HIPROC'}
        symtab_section[i]['type'] = st_type[symtab_section[i]['info'] & 0xf]

        if symtab_section[i]['type'] == 'FUNC':
            labels[symtab_section[i]['value']] = symtab_section[i]['name'] + ':'

        st_visibility = ['DEFAULT', 'INTERNAL', 'HIDDEN', 'PROTECTED']
        symtab_section[i]['vis'] = st_visibility[symtab_section[i]['other'] & 3]

        shndx = {0: 'UNDEF', 0xff00: 'LOPROC', 0xff1f: 'HIPROC',
                 0xfff1: 'ABS', 0xfff2: 'COMMON', 0xffff: 'HIRESERVE'}
        if symtab_section[i]['shndx'] in shndx:
            symtab_section[i]['shndx'] = shndx[symtab_section[i]['shndx']]

    return symtab_section


def get_label(address):
    global labels, loc

    if address in labels:
        return labels[address][:-1]

    labels[address] = f'LOC_{hex(loc)[2:].rjust(5, "0")}:'
    loc += 1
    return labels[address][:-1]


def parse_text(text_header):
    global source, offset

    reg_names = ['zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
                 's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
                 'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7',
                 's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6']
    reg_comp = ['s0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5']
    
    offset = text_header['offset']
    text_section = []

    while offset < len(source) and offset < text_header['offset'] + text_header['size']:
        address = offset - text_header['offset'] + text_header['addr']
        line = [address, '', '']

        if bin(source[offset])[-2:] == '11':
            command = read_bin(4)
            
            if command[25:] == '0110011':  # R
                r_type = [['add', 'sll', 'slt', 'sltu', 'xor', 'srl', 'or', 'and'],
                          ['sub', 'UC', 'UC', 'UC', 'UC', 'sra', 'UC', 'UC'],
                          ['mul', 'mulh', 'mulhsu', 'mulhu', 'div', 'divu', 'rem', 'remu']]

                rs2 = reg_names[int(command[7:12], 2)]
                rs1 = reg_names[int(command[12:17], 2)]
                func3 = int(command[17:20], 2)
                rd = reg_names[int(command[20:25], 2)]
                
                if command[:7] == '0000000':
                    ins = r_type[0][func3]
                elif command[:7] == '0100000':
                    ins = r_type[1][func3]
                elif command[:7] == '0000001':
                    ins = r_type[2][func3]
                else:
                    ins = 'UC'

                line[2] = f'{ins} {rd}, {rs1}, {rs2}'

            elif command[25:27] == '00' and command[28:] == '0011':  # I
                i_type = [['lb', 'lh', 'lw', 'UC', 'lbu', 'lhu', 'UC', 'UC'],
                          ['addi', 'slli', 'slti', 'sltiu', 'xori', 'srli', 'ori', 'andi']]

                imm = int(command[:12], 2)
                rs1 = reg_names[int(command[12:17], 2)]
                func3 = int(command[17:20], 2)
                rd = reg_names[int(command[20:25], 2)]

                if command[27] == '0':
                    ins = i_type[0][func3]
                    imm -= int(command[0]) * 2 ** 12

                    line[2] = f'{ins} {rd}, {imm}({rs1})'
                else:
                    ins = i_type[1][func3]
                    if ins == 'slli' and command[:7] == '0000000':
                        imm = int(command[7:12], 2)
                    elif ins == 'srli' and command[:7] == '0000000':
                        imm = int(command[7:12], 2)
                    elif ins == 'srli' and command[:7] == '0100000':
                        ins = 'srai'
                        imm = int(command[7:12], 2)
                    elif ins != 'srli':
                        imm -= int(command[0]) * 2 ** 12
                    else:
                        ins = 'UC'

                    line[2] = f'{ins} {rd}, {rs1}, {imm}'

            elif command[17:20] == '000' and command[25:] == '1100111':
                imm = int(command[:12], 2) - int(command[0]) * 2 ** 12
                rs1 = reg_names[int(command[12:17], 2)]
                rd = reg_names[int(command[20:25], 2)]

                line[2] = f'jalr {rd}, {imm}({rs1})'

            elif command == '00000000000000000000000001110011':
                line[2] = 'ecall'

            elif command == '00000000000100000000000001110011':
                line[2] = 'ebreak'

            elif command[25:] == '0100011':  # S
                imm = int(command[:7] + command[20:25], 2) - int(command[0]) * 2 ** 12
                rs2 = reg_names[int(command[7:12], 2)]
                rs1 = reg_names[int(command[12:17], 2)]
                func3 = int(command[17:20], 2)

                if func3 == 0:
                    ins = 'sb'
                elif func3 == 1:
                    ins = 'sh'
                elif func3 == 2:
                    ins = 'sw'
                else:
                    ins = 'UC'

                line[2] = f'{ins} {rs2}, {imm}({rs1})'

            elif command[25:] == '1100011':  # B
                b_type = ['beq', 'bne', 'UC', 'UC', 'blt', 'bge', 'bltu', 'bgeu']

                imm = command[24] + command[1:7] + command[20:24] + '0'
                imm = int(imm, 2) - int(command[0]) * 2 ** 12

                rs2 = reg_names[int(command[7:12], 2)]
                rs1 = reg_names[int(command[12:17], 2)]
                func3 = int(command[17:20], 2)

                ins = b_type[func3]

                if ins != 'UC':
                    imm = get_label(address + imm)

                line[2] = f'{ins} {rs1}, {rs2}, {imm}'

            elif command[25] == '0' and command[27:] == '10111':  # U
                imm = int(command[:20] + '0' * 12, 2) - int(command[0]) * 2 ** 32
                rd = reg_names[int(command[20:25], 2)]

                if command[26] == '1':
                    ins = 'lui'
                else:
                    ins = 'auipc'

                line[2] = f'{ins} {rd}, {imm}'

            elif command[25:] == '1101111':  # J
                imm = command[12:20] + command[11] + command[1:11] + '0'
                imm = int(imm, 2) - int(command[0]) * 2 ** 20
                rd = reg_names[int(command[20:25], 2)]

                imm = get_label(address + imm)

                line[2] = f'jal {rd}, {imm}'

            elif command[25:] == '1110011':  # CSR
                csr_ins = ['UC', 'csrrw', 'csrrs', 'csrrc', 'UC', 'csrrwi', 'csrrsi', 'csrrci']

                csr_names = {0x001: 'fflags', 0x002: 'frm', 0x003: 'fcsr', 0xC00: 'cycle',
                             0xC01: 'time', 0xC02: 'instret', 0xC80: 'cycleh', 0xC81: 'timeh',
                             0xC82: 'instreth', 0x100: 'sstatus', 0x101: 'stvec', 0x104: 'sie',
                             0x121: 'stimecmp', 0xD01: 'stime', 0xD81: 'stimeh', 0x140: 'sscratch',
                             0x141: 'sepc', 0xD42: 'scause', 0xD43: 'sbadaddr', 0x144: 'sip',
                             0x180: 'sptbr', 0x181: 'sasid', 0x900: 'cyclew', 0x901: 'timew',
                             0x902: 'instretw', 0x980: 'cyclehw', 0x981: 'timehw', 0x982: 'instrethw',
                             0x200: 'hstatus', 0x201: 'htvec', 0x202: 'htdeleg', 0x221: 'htimecmp',
                             0xE01: 'htime', 0xE81: 'htimeh', 0x240: 'hscratch', 0x241: 'hepc',
                             0x242: 'hcause', 0x243: 'hbadaddr', 0xA01: 'stimew', 0xA81: 'stimehw',
                             0xF00: 'mcpuid', 0xF01: 'mimpid', 0xF10: 'mhartid', 0x300: 'mstatus',
                             0x301: 'mtvec', 0x302: 'mtdeleg', 0x304: 'mie', 0x321: 'mtimecmp',
                             0x701: 'mtime', 0x741: 'mtimeh', 0x340: 'mscratch', 0x341: 'meps',
                             0x342: 'mcause', 0x343: 'mbadaddr', 0x344: 'mip', 0x380: 'mbase',
                             0x381: 'mbound', 0x382: 'mibase', 0x383: 'mibound', 0x384: 'mdbase',
                             0x385: 'mdbound', 0xB01: 'htimew', 0xB81: 'htimehw', 0x780: 'mtohost',
                             0x781: 'mfromhost'}

                csr = int(command[:12], 2)
                rs1 = int(command[12:17], 2)
                func3 = int(command[17:20], 2)
                rd = reg_names[int(command[20:25], 2)]

                csr = csr_names.get(csr, csr)
                ins = csr_ins[func3]
                if ins in ['csrrw', 'csrrs', 'csrrc']:
                    rs1 = reg_names[rs1]

                line[2] = f'{ins} {rd}, {csr}, {rs1}'

            else:
                line[2] = 'UC'
        else:
            command = read_bin(2)

            if command[14:] == '00':
                if command[:3] == '000' and command != '0' * 16:
                    imm = command[5:9] + command[3:5] + command[10] + command[9] + '00'
                    imm = int(imm, 2) - int(command[5]) * 2 ** 10
                    rd = reg_comp[int(command[11:14], 2)]

                    line[2] = f'c.addi4spn {rd}, sp, {imm}'

                elif command[:3] == '010':
                    imm = command[10] + command[3:6] + command[9] + '00'
                    imm = int(imm, 2)
                    rs1 = reg_comp[int(command[6:9], 2)]
                    rd = reg_comp[int(command[11:14], 2)]

                    line[2] = f'c.lw {rd}, {imm}({rs1})'

                elif command[:3] == '110':
                    imm = command[10] + command[3:6] + command[9] + '00'
                    imm = int(imm, 2)
                    rs1 = reg_comp[int(command[6:9], 2)]
                    rs2 = reg_comp[int(command[11:14], 2)]

                    line[2] = f'c.sw {rs2}, {imm}({rs1})'
                else:
                    line[2] = 'UC'

            elif command[14:] == '01':
                if command[:3] == '000' and command[4:9] == '0' * 5:
                    line[2] = 'c.nop'
                elif command[:3] in ['000', '010'] and command[4:9] != '0' * 5:
                    imm = int(command[9:14], 2) - int(command[3]) * 2 ** 5
                    rd = reg_names[int(command[4:9], 2)]

                    if command[:3] == '000':
                        ins = 'c.addi'
                    else:
                        ins = 'c.li'

                    line[2] = f'{ins} {rd}, {imm}'

                elif command[1:3] == '01':
                    imm = command[7] + command[5:7] + command[9] + command[8] + command[13] + command[4] + command[10:13] + '0'
                    imm = int(imm, 2) - int(command[3]) * 2 ** 11

                    imm = get_label(address + imm)

                    if command[0] == '0':
                        ins = 'c.jal'
                    else:
                        ins = 'c.j'

                    line[2] = f'{ins} {imm}'

                elif command[:3] == '011' and command[4:9] != '0' * 5:
                    if command[4:9] == '00010':
                        imm = command[11:13] + command[10] + command[13] + command[9] + '0000'
                        imm = int(imm, 2) - int(command[3]) * 2 ** 9
                        rd = reg_names[int(command[4:9], 2)]

                        line[2] = f'c.addi16sp sp, {imm}'
                    else:
                        imm = int(command[9:14] + '0' * 12, 2) - int(command[3]) * 2 ** 17
                        rd = reg_names[int(command[4:9], 2)]

                        line[2] = f'c.lui {rd}, {imm}'

                elif command[:3] == '100':
                    if command[4:6] != '11':
                        imm = int(command[9:14], 2) - int(command[3]) * 2 ** 5
                        rd = reg_comp[int(command[6:9], 2)]

                        if command[4:6] == '00' and imm != 0:
                            ins = 'c.srli'
                        elif command[4:6] == '01' and imm != 0:
                            ins = 'c.srai'
                        elif command[4:6] == '10':
                            ins = 'c.andi'
                        else:
                            ins = 'UC'

                        line[2] = f'{ins} {rd}, {imm}'

                    elif command[3] == '0':
                        ins = ['c.sub', 'c.xor', 'c.or', 'c.and']
                        
                        rd = reg_comp[int(command[6:9], 2)]
                        func2 = int(command[9:11], 2)
                        rs2 = reg_comp[int(command[11:14], 2)]

                        ins = ins[func2]

                        line[2] = f'{ins} {rd}, {rs2}'
                    else:
                        line[2] = 'UC'

                elif command[:2] == '11':
                    imm = command[9:11] + command[13] + command[4:6] + command[11:13] + '0'
                    imm = int(imm, 2) - int(command[3]) * 2 ** 8
                    rs1 = reg_comp[int(command[6:9], 2)]

                    if command[2] == '0':
                        ins = 'c.beqz'
                    else:
                        ins = 'c.bnez'

                    imm = get_label(address + imm)

                    line[2] = f'{ins} {rs1}, {imm}'
                else:
                    line[2] = 'UC'
            else:
                if command[:3] == '000' and command[3] + command[9:14] != '0' * 6 and command[4:9] != '0' * 5:
                    imm = int(command[9:14], 2) - int(command[3]) * 2 ** 4
                    rd = reg_names[int(command[4:9], 2)]

                    line[2] = f'c.slli {rd}, {imm}'

                elif command[:3] == '010' and command[4:9] != '0' * 5:
                    imm = int(command[12:14] + command[3] + command[9:12] + '0' * 2, 2)
                    rd = reg_names[int(command[4:9], 2)]

                    line[2] = f'c.lwsp {rd}, {imm}(sp)'

                elif command[:3] == '100':
                    rs1 = reg_names[int(command[4:9], 2)]
                    rs2 = reg_names[int(command[9:14], 2)]

                    if command[3] == '0':
                        if rs1 != 'zero' and rs2 == 'zero':
                            line[2] = f'c.jr {rs1}'
                        elif rs1 != 'zero' and rs2 != 'zero':
                            line[2] = f'c.mv {rs1}, {rs2}'
                        else:
                            line[2] = 'UC'
                    else:
                        if rs1 == 'zero' and rs2 == 'zero':
                            line[2] = f'c.ebreak'
                        elif rs1 != 'zero' and rs2 == 'zero':
                            line[2] = f'c.jalr {rs1}'
                        elif rs1 != 'zero' and rs2 != 'zero':
                            line[2] = f'c.add {rs1}, {rs2}'
                        else:
                            line[2] = 'UC'

                elif command[:3] == '110':
                    imm = int(command[7:9] + command[3:7] + '0' * 2, 2)
                    rs2 = reg_names[int(command[9:14], 2)]

                    line[2] = f'c.swsp {rs2}, {imm}(sp)'
                else:
                    line[2] = 'UC'

        if 'UC' in line[2]:
            line[2] = 'unknown_command'

        text_section.append(line)

    return text_section


def write_result(text_section, symtab_section):
    global labels

    try:
        output_file = open(sys.argv[2], 'w')
        output_file.write('.text\n')

        for line in text_section:
            line[1] = labels.get(line[0], '')
            output_file.write('{:08x} {:>11s} {:<s}\n'.format(*line))

        output_file.write('\n.symtab\nSymbol Value              Size Type     Bind     Vis       Index Name\n')

        for i in range(len(symtab_section)):
            line = symtab_section[i]

            pattern = '[{:>4d}] 0x{:<15x} {:>5d} {:<8s} {:<8s} {:<8s} {:>6s} {:<s}\n'
            output_file.write(pattern.format(i, line['value'], line['size'], line['type'],
                                             line['bind'], line['vis'], str(line['shndx']), line['name']))

        output_file.close()
    except IOError:
        print('Error while writing file')
        sys.exit()


def main():
    read_elf()

    e_shoff, e_shentsize, e_shnum, e_shstrndx = parse_header()
    text_header, symtab_header, strtab_header = parse_section_headers(e_shoff, e_shentsize, e_shnum, e_shstrndx)

    symtab_section = parse_symtab(symtab_header, strtab_header)
    text_section = parse_text(text_header)

    write_result(text_section, symtab_section)


if __name__ == "__main__":
    main()
