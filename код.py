
# -*- coding: UTF-8 -*-


class SimplifiedDES(object):
    """Simplified DES is a simplified version of DES algorithm"""

    # Key size in bits
    key_size = 10

    """ Tables for initial and final permutations (b1, b2, b3, ... b8) """
    ## Initial permutation
    #IP_table = (2, 6, 3, 1, 4, 8, 5, 7)

    ## Final permutation (Inverse of intial)
    #FP_table = (4, 1, 3, 5, 7, 2, 8, 6)

    """ Tables for the fk function """
    # Expansion permutation
    EP_table = (4, 1, 3, 4, 2, 1, 3, 2)

    # Substitution Box 0
    S0_table = (1, 0, 2, 3, 1, 2, 0, 3, 1, 3, 2, 0, 0, 3, 2, 1)

    # Substitution Box 1
    S1_table = (1, 0, 2, 1, 3, 3, 0, 3, 2, 1, 3, 0, 0, 2, 1, 2)

    # Permutation Table
    P4_table = (4, 2, 1, 3)

    def __init__(self, key):
        self.key = key

    def _perm(self, inputByte, permTable):
        """Permute input byte according to permutation table

        :param inputByte: byte to permute
        :param permTable: table to use for permutation
        :returns: permuted byte
        """
        outputByte = 0
        for index, elem in enumerate(permTable):
            if index >= elem:
                outputByte |= (inputByte & (128 >> (elem - 1))) >> (index - (elem - 1))
            else:
                outputByte |= (inputByte & (128 >> (elem - 1))) << ((elem - 1) - index)

        return outputByte

    def ip(self, inputByte):
        """Perform the initial permutation on data"""
        return self._perm(inputByte, self.IP_table)

    def fp(self, inputByte):
        """Perform the final permutation on data """
        return self._perm(inputByte, self.FP_table)

    def swap_nibbles(self, inputByte):
        """Swap the two nibbles of the byte """
        return (inputByte << 4 | inputByte >> 4) & 0xFF

    def left_shift(self, keyBitList):
        """Perform a circular left shift on the first and second set of five bits

        before = | 1| 2| 3| 4| 5| 6| 7| 8| 9|10|
        after  = | 2| 3| 4| 5| 1| 7| 8| 9|10| 6|

        :param keyBitList: list of bits
        :returns: circularly left shifted list of bits
        """
        shiftedKey = [None] * self.key_size
        shiftedKey[0:9] = keyBitList[1:10]
        shiftedKey[4] = keyBitList[0]
        shiftedKey[9] = keyBitList[5]

        return shiftedKey

   
    def F(self, sKey, rightNibble):
        #print(bin(rightNibble))
        #print(bin(sKey))
        """Round function
        1. Expansion Permutation Box
        2. XOR
        3. Substitution Boxes
        4. Permutation

        :param sKey: subkey to be used to for this round
        :param rightNibble: right nibble of the 8 bit input to this round
        :returns: 4 bit output
        """
        # Right nibble is permuted using EP and XOR'd with first key
        aux = sKey ^ self._perm(self.swap_nibbles(rightNibble), self.EP_table)

        #print(bin(aux^sKey))
        #print(bin(aux))

        # Find indices into the S-box S0
        index0 = (aux & 0xF0) >> 4

        # Find indices into the S-box S1
        index1 = aux & 0x0F

        #print(index0, index1)
        #print(self.S1_table[index1], self.S0_table[index0])

        # S0(b1b2b3b4) = the [ b1b4 , b2b3 ] cell from the "S-box" S0
        # and similarly for S1
        sboxOutputs = self.swap_nibbles (
            (self.S0_table[index0] << 2) + self.S1_table[index1]
        )
        #print(sboxOutputs)

        # Apply permutation
        return self._perm(sboxOutputs, self.P4_table)

    def fk(self, subKey, inputData):
        """Apply Feistel function on data with given subkey

        :param subKey: subkey to be used to for this round
        :param inputData: 8 bit input for this round
        :returns: 8 bit output
        """
        # Divide the permuted bits into 2 halves
        leftNibble = inputData & 0xF0
        rightNibble = inputData & 0x0F

        # Apply F
        FOutput = self.F(subKey, rightNibble)

        # Return left nibble and right nibble
        return (leftNibble ^ FOutput) | rightNibble

    def encrypt(self, plaintext):
        """Encrypt plaintext with given key

        ciphertext = IP^-1( fK2( SW( fK1( IP( plaintext ) ) ) ) )

        Example::

            ciphertext = SimplifiedDES(3).encrypt(0b10101111)

        :param plaintext: 8 bit plaintext
        :returns: 8 bit ciphertext
        """

        for i in range (0, 36):
            plaintext = self.fk(self.key, plaintext)
            plaintext = self.swap_nibbles(plaintext)

        last_round_output = self.fk(self.key, plaintext)

        return (last_round_output)

   

P4_inverse = (3, 2, 4 ,1)
s0_table_1 = []
s1_table_1 = []





def perm_4(inputByte,permTable):
    outputByte = 0
    for index, elem in enumerate(permTable):
        if index >= elem:
            outputByte |= (inputByte & (8 >> (elem - 1))) >> (index - (elem - 1))
        else:
            outputByte |= (inputByte & (8 >> (elem - 1))) << ((elem - 1) - index)
    return outputByte


def number_to_bits(number, len):
    bits = ""
    for i in range(len):
        if (number) & ((1<<len-1)>>i): bits = bits + '1'
        else: bits = bits + '0'
    return bits

def bits_to_number(bits):
    number = 0
    for i in range (len(bits)):
        if bits[i]=="1":
            number|= 1<<(len(bits)-1-i)
    return(number)


def find_texts(a, pairs_x, pairs_y):
    mask = 0b1100
    for i in range(16):
        for j in range (16):
            ciphertext_1 = a.encrypt((i<<4)|mask)
            ciphertext_2 = a.encrypt((mask<<4)|j)
            if (ciphertext_1 & 0xF0) >> 4 == (ciphertext_2 & 0x0F):
                pairs_x.append([(i<<4)|mask, (mask<<4)|j])
                pairs_y.append([ciphertext_1, ciphertext_2])
                break




def find_key(a, pair_x, pair_y, keys):
    keys_1_x = set()
    keys_2_x = set()
    keys_1_y = set()
    keys_2_y = set()


    print("открытый текст",bin(pair_x[0]),bin(pair_x[1]))
    output=((pair_x[0]&0xF0)>>4)^(pair_x[1]&0x0F)
    output=perm_4(output,P4_inverse)
    print("выход F до прохождения перестановки", bin(output))

    input = a._perm(a.swap_nibbles(pair_x[0]&0x0F), a.EP_table)
    print("выход F после прохождения перестановки с росширениям", bin(input))

    for i in range (len(a.S0_table)):
        if a.S0_table[i]==((output&0xc)>>2):
            keys_1_x.add(i^((input&0xF0)>>4))
        if a.S1_table[i]==(output&0x3):
            keys_2_x.add(i^(input&0x0F))

    print("вероятные левые подключи для очередное пары", keys_1_x)
    print("Вероятные правые подключи для очередной пары ",keys_2_x)


    print("Шифртексты",bin(pair_y[0]),bin(pair_y[1]))
    output=(pair_y[0]&0x0F)^((pair_y[1]&0xF0)>>4)
    output=perm_4(output, P4_inverse)
    output=perm_4(output,P4_inverse)
    print("выход F до прохождения перестановки:", bin(output))

    input=a._perm(pair_y[0]&0xF0,a.EP_table)
    print("вход F после прохождения перестановки с расширением:", bin(input))
    for i in range (len(a.S0_table)):
        if a.S0_table[i]==((output&0xc)>>2):
            keys_1_y.add(i^((input&0xF0)>>4))
        if a.S1_table[i]==(output&0x3):
            keys_2_y.add(i^(input&0x0F))

    print("Аналогичные левые подключи для пары на последнем раунде шифрования",keys_1_y)
    print("Аналогичные правые подключи для пары на последнем раунде шифрования",keys_2_y)
    subkeys_1=keys_1_x&keys_1_y
    subkeys_2=keys_2_x&keys_2_y

    print("Пересечение для множеств левых подключей",subkeys_1)
    print("Пересечение для множеств правых подключей",subkeys_2)
    if len(subkeys_1)!=0 and len(subkeys_2)!=0:
        for i in subkeys_1:
            for j in subkeys_2:

                print(number_to_bits(i,4)+number_to_bits(j,4))
                print("Вероятный ключ для очередной пары", bits_to_number(number_to_bits(i,4)+number_to_bits(j,4)))
                keys[bits_to_number(number_to_bits(i,4)+number_to_bits(j,4))]+=1





a = SimplifiedDES(130)
pairs_x = []
pairs_y = []

find_texts(a, pairs_x, pairs_y)
print("Возможные открытые тексты слайдовых пар:")
print(pairs_x)

print("Возможные шифртексты слайдовых пар:")
print(pairs_y)

keys=[0]*256


for i in range(len(pairs_x)):
    find_key(a, pairs_x[i], pairs_y[i], keys)
    print()


max = max(keys)
print(keys)
print ("Ключ", a.key)
for i in range(len(keys)):
    if keys[i]==max: print("Найденный ключ:", i)