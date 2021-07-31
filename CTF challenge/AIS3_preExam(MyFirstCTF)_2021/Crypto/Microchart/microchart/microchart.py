import rng
import ast


input_file = open('input.txt', 'r')
data_file = open('data.txt', 'r', newline='\r\n')

flag = input('enter flag: ').strip().encode()
rec = ast.literal_eval(input('enter recurrence: '))

rand = rng.RNG(flag, rec)

# read input and generate
bpm = int(input_file.readline())
offset = int(input_file.readline())
ms_per_bar = 60000.0 / bpm * 4

notes = []
time = offset

for line in input_file:
    count, beat = map(int, line.strip().split(','))
    for i in range(count):
        for j in range(beat):
            note_x = rand.get_byte() * 2
            note_time = int(time + ms_per_bar * (i + j / beat))
            notes.append((note_x, note_time))
    time += count * ms_per_bar

# write to output file
output_file = open('microchart.osu', 'w')
output_file.write(data_file.read())
first = True
for x, t in notes:
    if first:
        output_file.write(f'{x},192,{t},5,0,0:0:0:0:\r\n')
        first = False
    else:
        output_file.write(f'{x},192,{t},1,0,0:0:0:0:\r\n')
