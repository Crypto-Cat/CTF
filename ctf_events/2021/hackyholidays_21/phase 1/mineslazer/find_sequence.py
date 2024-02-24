from pwn import *

context.log_level = 'warning'

# https://lemire.me/blog/2017/08/22/cracking-random-number-generators-xoroshiro128/
# set number of clients, then paste the result of this script as input for xoroshiftall.py
# take the next value in sequence and use as input for the solve_game.py script
# e.g. if client count is 3, use the vals in xoroshiftall and use 4th val from output in solve_game
client_count = 3
clients = []
u64_vals = []

#  _ = blank space
#  X = bomb
#  D = detonated bomb

for i in range(client_count):
    # Create new remote connection
    clients.append(remote('127.0.0.1', '1234'))
    warning('game %d', i)
    lost_game = False
    # Try to complete a game
    for x in range(8):
        for y in range(8):
            # Make moves until we lose
            if not lost_game:
                clients[i].sendlineafter('Enter laser position: ', str(x) + ',' + str(y))
                result = clients[i].recvline()
                # Lose the game
                if b'Yikes, you hit something you weren\'t supposed to hit.' in result:
                    lost_game = True
                    clients[i].recvline()
                    # Save the correct board state - stripping anything we dont need
                    correct_board_state = clients[i].recvallS().replace('[', '').replace(']', '').replace('\r\n', '')
                    # Convert to binary
                    binary_board = correct_board_state.replace('Ｘ', '1').replace('Ｄ', '1').replace('＿', '0')
                    info("binary board: %s", binary_board)
                    # Due to the way the nimscript set/clear/testBit works (LSB), we need to reverse each byte
                    reversed_bytes = ''.join([binary_board[k:k + 8][::-1] for k in range(0, len(binary_board), 8)])
                    info("reversed:     %s", binary_board)
                    # Convert to unsigned 64-bit int (hex)
                    u64_value = p64(int(reversed_bytes, 2), signed='unsigned')
                    warning('u64: 0x%s\n\n', u64_value.hex())
                    u64_vals.append('0x' + str(u64_value.hex()))

# paste this into xoroshiftall.py
print('python xoroshiftall.py ' + ' '.join(u64_vals))
