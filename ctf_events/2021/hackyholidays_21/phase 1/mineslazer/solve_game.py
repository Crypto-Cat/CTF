from pwn import *
import sys

context.log_level = 'warning'

if len(sys.argv) < 2:
    print('please supply u64 value to generate grid e.g. 0x9585e76a11116455')
    exit(0)

# this is the next u64 in the sequence, predicted by xoroshiftall.py
seed = sys.argv[1]

#  _ = blank space
#  X = bomb
#  D = detonated bomb
binary = f'{int(seed, 16):0>64b}'
binary_board = [binary[k:k + 8][::-1] for k in range(0, len(binary), 8)][::-1]
warning("predicted board: %s", ''.join(binary_board))

# Create new remote connection
client = remote('127.0.0.1', '1234')

# Solve game
for x, byte in enumerate(binary_board):
    for y, bit in enumerate(byte):
        if bit == '1':
            client.sendlineafter('Enter laser position: ', str(y) + ',' + str(x))
            result = client.recvline()
            if b'Yikes, you hit something you weren\'t supposed to hit.' in result:
                client.recvline()
                # Save the correct board state - stripping anything we dont need
                correct_board_state = client.recvallS().replace('[', '').replace(']', '').replace('\r\n', '')
                # Convert to binary
                binary_board = correct_board_state.replace('Ｘ', '1').replace('Ｄ', '1').replace('＿', '0')
                warning("actual board:    %s", binary_board)

# Flag?
client.interactive()
