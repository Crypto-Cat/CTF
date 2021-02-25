import re
from word2number import w2n
import numpy as np

powers = {
    'hundred': (10 ** 2),
    'thousand': (10 ** 3),
    'million': (10 ** 6),
    'billion': (10 ** 9),
    'trillion': (10 ** 12),
    'quadrillion': (10 ** 15),
    'quintillion': (10 ** 18),
    'sextillion': (10 ** 21),
    'septillion': (10 ** 24),
    'octillion': (10 ** 27),
    'nonillion': (10 ** 30),
    'decillion': (10 ** 33),
    'undecillion': (10 ** 36),
    'duodecillion': (10 ** 39),
    'tredecillion': (10 ** 42),
    'quattuordecillion': (10 ** 45),
    'quindecillion': (10 ** 48),
    'sexdecillion': (10 ** 51),
    'septemdecillion': (10 ** 54),
    'octodecillion': (10 ** 57),
    'novemdecillion': (10 ** 60),
    'vigintillion': (10 ** 63),
    'vigintunillion': (10 ** 66),
    'unvigintillion': (10 ** 66),
    'duovigintillion': (10 ** 69),
    'vigintiduoillion': (10 ** 69),
    'vigintitrillion': (10 ** 72),
    'trevigintillion': (10 ** 72),
    'vigintiquadrillion': (10 ** 75),
    'quattuorvigintillion': (10 ** 75),
    'quinvigintillion': (10 ** 78),
    'vigintiquintrillion': (10 ** 78),
    'vigintisextillion': (10 ** 81),
    'sexvigintillion': (10 ** 81),
    'vigintiseptillion': (10 ** 84),
    'septvigintillion': (10 ** 84),
    'octovigintillion': (10 ** 87),
    'vigintoctillion': (10 ** 87),
    'vigintinonillion': (10 ** 90),
    'nonvigintillion': (10 ** 90),
    'trigintillion': (10 ** 93),
    'untrigintillion': (10 ** 96),
    'duotrigintillion': (10 ** 99),
    'googol': (10 ** 100),
    'centillion': (10 ** 303),
    'one': 1
}

# Coordinates transcribed using IBM Watson (and some manual assistance)
coords_set_list = [
    [
        "one hundred forty one quindecillion two hundred five quattuordecillion nine hundred fifty three tredecillion nine hundred seventy five duodecillion four hundred fifty two undecillion seven hundred thirty five decillion five hundred ninety nonillion four hundred ninety six octillion three hundred twenty four septillion sixty five sextillion eighty five quintillion four hundred forty one quadrillion nine hundred eighty four trillion five hundred fifty two billion four hundred twenty nine million one hundred four thousand four hundred three",

        "three hundred seventy nine quindecillion five hundred seventy quattuordecillion five hundred fifty nine tredecillion one hundred seventy five duodecillion one hundred fourteen undecillion four hundred eighty six decillion seven hundred eight nonillion one hundred three octillion fourteen septillion four hundred eighty two sextillion two hundred fifty five quintillion five hundred sixteen quadrillion one hundred two trillion seven hundred eleven billion seven hundred eighty five million two hundred thirty two thousand ninety three"
    ],
    [
        "one hundred seventy five quindecillion eight hundred sixty five quattuordecillion four hundred ninety seven tredecillion four hundred ninety nine duodecillion two hundred eighty four undecillion five hundred eighty six decillion four hundred sixty four nonillion one hundred eighty eight octillion six hundred eleven septillion one hundred fifty six sextillion four hundred quintillion three hundred twenty five quadrillion seven hundred thirty nine trillion nine hundred thirty six billion six hundred forty four million three hundred thirty nine thousand seven hundred seventy two",

        "eighty two quindecillion four hundred seven quattuordecillion six hundred seventy three tredecillion two hundred eighty eight duodecillion seven hundred eighteen undecillion one hundred eighty decillion seventy one nonillion fifty four octillion four hundred sixty four septillion three hundred ninety four sextillion twenty one quintillion two hundred thirty three quadrillion three hundred seventy two trillion five hundred nine billion three hundred ninety million seven hundred fifty four thousand eight hundred one"
    ],
    [
        "fifty six quattuordecillion fifteen tredecillion six hundred forty four duodecillion one hundred ninety seven undecillion three hundred four decillion one hundred twenty nonillion nine hundred forty eight octillion one hundred ten septillion six hundred twenty two sextillion forty six quintillion eight hundred seventy quadrillion forty trillion four hundred eighty five billion eight hundred twenty three million four hundred four thousand thirty nine",

        "twenty one quindecillion nine hundred forty seven quattuordecillion eight hundred seventy seven tredecillion nine hundred forty one duodecillion seven hundred forty four undecillion four hundred twenty decillion one hundred thirty five nonillion three hundred fifty seven octillion eight hundred thirty one septillion six hundred ninety sextillion eight hundred eighty six quintillion one hundred seventy four quadrillion five hundred seventy four trillion nine billion five hundred thirty nine million four hundred seventeen thousand one"
    ]
]

new_coords_set_list = []

# Loop through each set of coordinates
for i, coord_set in enumerate(coords_set_list):
    new_coord_set = []
    # Loop through x,y
    for j, coord in enumerate(coord_set):
        # Split string based on the suffix
        split_str = re.split(
            r"(million|billion|trillion|quadrillion|quintillion|sextillion|septillion|octillion|nonillion|decillion|undecillion|duodecillion|tredecillion|quattuordecillion|quindecillion|sexdecillion|septemdecillion|octodecillion|novemdecillion|vigintillion|vigintunillion|unvigintillion|duovigintillion|vigintiduoillion|vigintitrillion|trevigintillion|vigintiquadrillion|quattuorvigintillion|quinvigintillion|vigintiquintrillion|vigintisextillion|sexvigintillion|vigintiseptillion|septvigintillion|octovigintillion|vigintoctillion|vigintinonillion|nonvigintillion|trigintillion|untrigintillion|duotrigintillion|googol|centillion)",
            coord)
        # Pad out the last value (which has no suffix)
        split_str.append("one")
        # Convert to 2D array
        numbers_2d = np.reshape(split_str, (-1, 2))
        # For the final value
        total = 0
        # Loop through each prefix + suffix extracted from the split
        for prefix, suffix in numbers_2d:
            # Convert prefix to number (1 billion max) and multiply by suffix
            #print(str(w2n.word_to_num(str(prefix))) + " * " + suffix)
            result = w2n.word_to_num(str(prefix)) * powers[suffix]
            # print(result)
            total += int(result)
        # Print out the resulting coordinate
        print("[" + str(i) + "]" + "[" + str(j) + "] = " + str(total))
        # Save the new coordinates (for centroid later)
        new_coord_set.append(total)
    new_coords_set_list.append(new_coord_set)
    print("")

# Calculate centroid of points (manually)
oX = (new_coords_set_list[0][0] + new_coords_set_list[1][0] + new_coords_set_list[2][0]) / 3
oY = (new_coords_set_list[0][1] + new_coords_set_list[1][1] + new_coords_set_list[2][1]) / 3
# Convert to hex for our flag
print(hex(oX))
print(hex(oY))
