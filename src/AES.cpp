#include "AES.hpp"

AES::AES(AESKey aes_key)
{
    switch (aes_key) {
        case AESKey::AES_128:
            this->Nk = 4;
            this->Nr = 10;
            break;
        case AESKey::AES_192:
            this->Nk = 6;
            this->Nr = 12;
            break;
        case AESKey::AES_256:
            this->Nk = 8;
            this->Nr = 14;
            break;
    }
}

std::vector<unsigned char> AES::encrypt(std::vector<unsigned char> plaintext,
        std::vector<unsigned char> key) {

    addPadding(plaintext, state_size);

    std::vector<unsigned char> ciphertext;
    ciphertext.reserve(plaintext.size());
    std::vector<unsigned char> expandedKey = KeyExpansion(key);

    for (int i = 0; i < plaintext.size(); i += state_size) {
        std::vector<std::vector<unsigned char>> state = makeState(plaintext, i);
        std::vector<std::vector<unsigned char>> roundKey = makeState(expandedKey, 0);

        AddRoundKey(state, roundKey);

        for (int j = 0; j < Nr - 1; ++j) {
            roundKey = makeState(expandedKey, (j + 1) * state_size);
            Round(state, roundKey);
        }
        roundKey = makeState(expandedKey, Nr * state_size);
        FinalRound(state, roundKey);

        std::vector<unsigned char> encryptedState = unmakeState(state);
        ciphertext.insert(ciphertext.end(), encryptedState.begin(), encryptedState.end());
    }

    return ciphertext;
}

std::vector<unsigned char> AES::decrypt(std::vector<unsigned char> cipher,
        std::vector<unsigned char> key) {

    // TODO: check cipher length
    std::vector<unsigned char> plaintext;
    plaintext.reserve(cipher.size());
    std::vector<unsigned char> expandedKey = InvKeyExpansion(key);

    for (int i = 0; i < cipher.size(); i += state_size) {
        std::vector<std::vector<unsigned char>> state = makeState(cipher, i);
        std::vector<std::vector<unsigned char>> roundKey = makeState(expandedKey, Nr * state_size);

        InvAddRoundKey(state, roundKey);

        for (int j = Nr - 1; j > 0; --j) {
            roundKey = makeState(expandedKey, j * state_size);
            InvRound(state, roundKey);
        }
        roundKey = makeState(expandedKey, 0);
        InvFinalRound(state, roundKey);

        std::vector<unsigned char> decryptedState = unmakeState(state);
        plaintext.insert(plaintext.end(), decryptedState.begin(), decryptedState.end());
    }

    removePadding(plaintext);
    return plaintext;
}

void AES::addPadding(std::vector<unsigned char>& data, int multipleBy) {
    unsigned char paddingSize = 16 - (data.size() % multipleBy);
    for (int i = 0; i < paddingSize; ++i) {
        data.push_back(paddingSize);
    }
}

void AES::removePadding(std::vector<unsigned char>& data) {
    unsigned char paddingSize = data.back();
    for (int i = 0; i < paddingSize; ++i) {
        data.pop_back();
    }
}

void AES::Round(std::vector<std::vector<unsigned char>>& state,
        std::vector<std::vector<unsigned char>> roundKey) {
    ByteSub(state);
    ShiftRow(state);
    MixColumn(state);
    AddRoundKey(state, roundKey);
}

void AES::FinalRound(std::vector<std::vector<unsigned char>>& state,
        std::vector<std::vector<unsigned char>> roundKey) {
    ByteSub(state);
    ShiftRow(state);
    AddRoundKey(state, roundKey);
}

void AES::ByteSub(std::vector<std::vector<unsigned char>>& state) {
    for (auto& row : state) {
        for (auto& byte : row) {
            byte = SBOX[(byte >> 4) & 0xF][byte & 0xF];
        }
    }
}

void AES::ShiftRow(std::vector<std::vector<unsigned char>>& state) {
    for (int i = 0; i < Nb; ++i) {
        rorRow(state[i], i);
    }
}

void AES::MixColumn(std::vector<std::vector<unsigned char>>& state) {
    std::vector<std::vector<unsigned char>> temp(4, std::vector<unsigned char>(4));

    for (int i = 0; i < Nb; ++i) {
        for (int j = 0; j < 4; ++j) {
            for (int k = 0; k < 4; ++k) {
                if (CMDS[j][k] == 1) {
                    temp[j][i] ^= state[k][i];
                } else {
                    temp[j][i] ^= GF_MUL_TABLE[CMDS[j][k]][state[k][i]];
                }
            }
        }
    }
    state = temp;
}

void AES::AddRoundKey(std::vector<std::vector<unsigned char>>& state,
        std::vector<std::vector<unsigned char>>& key) {
    for (int i = 0; i < Nb; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] ^= key[i][j];
        }
    }
}

std::vector<unsigned char> AES::KeyExpansion(const std::vector<unsigned char> key) {
    std::vector<unsigned char> w; // 4 * Nb * (Nr + 1)

    for (int i = 0; i < Nk; ++i) {
        w.insert(w.end(), key.begin() + 4 * i, key.begin() + 4 * i + 4);
    }

    for (int i = 4 * Nk; i < (4 * Nb * (Nr + 1)); i += 4) {
        word temp(w.end() - 4, w.end());

        if (i / 4 % Nk == 0)
        {
            RotByte(temp);
            SubByte(temp);
            word rcon = Rcon(i / (4 * Nk));
            temp = EXOR(temp, rcon);
        } else if (Nk > 6 && i % Nk == 4) {
            SubByte(temp);
        }
        word wNk(w.end() - 4 * Nk, w.end() - 3 * Nk);
        word res = EXOR(wNk, temp);
        w.insert(w.end(), std::begin(res), std::end(res));
    }

    return w;
}

void AES::InvRound(std::vector<std::vector<unsigned char>>& state,
        std::vector<std::vector<unsigned char>> roundKey) {
    InvShiftRow(state);
    InvByteSub(state);
    InvAddRoundKey(state, roundKey);
    InvMixColumn(state);
}

void AES::InvFinalRound(std::vector<std::vector<unsigned char>>& state,
        std::vector<std::vector<unsigned char>> roundKey) {
    InvShiftRow(state);
    InvByteSub(state);
    InvAddRoundKey(state, roundKey);
}

void AES::InvByteSub(std::vector<std::vector<unsigned char>>& state) {
    for (auto& row : state) {
        for (auto& byte : row) {
            byte = INV_SBOX[(byte >> 4) & 0xF][byte & 0xF];
        }
    }
}

void AES::InvShiftRow(std::vector<std::vector<unsigned char>>& state) {
    for (int i = 0; i < Nb; ++i) {
        rorRow(state[i], Nb - i);
    }
}

void AES::InvMixColumn(std::vector<std::vector<unsigned char>>& state) {
    std::vector<std::vector<unsigned char>> temp(4, std::vector<unsigned char>(4));

    for (int i = 0; i < Nb; ++i) {
        for (int j = 0; j < 4; ++j) {
            for (int k = 0; k < 4; ++k) {
                if (INV_CMDS[j][k] == 1) {
                    temp[j][i] ^= state[k][i];
                } else {
                    temp[j][i] ^= GF_MUL_TABLE[INV_CMDS[j][k]][state[k][i]];
                }
            }
        }
    }
    state = temp;
}

void AES::InvAddRoundKey(std::vector<std::vector<unsigned char>>& state,
        std::vector<std::vector<unsigned char>>& key) {
    AddRoundKey(state, key);
}

std::vector<unsigned char> AES::InvKeyExpansion(const std::vector<unsigned char> key) {
    std::vector<unsigned char> extendedKey = KeyExpansion(key);

    for (int i = 1; i < Nr; ++i) {
        std::vector<std::vector<unsigned char>> extendedKeyState =
                makeState(extendedKey, i * state_size);

        InvMixColumn(extendedKeyState);
    }

    return extendedKey;
}

void AES::SubByte(word& w) {
    for (int i = 0; i < 4; ++i) {
        w[i] = SBOX[(w[i] >> 4) & 0xF][w[i] & 0xF];
    }
}

void AES::RotByte(word& w) {
    unsigned char ov = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = ov;
}

word AES::EXOR(word a, word b) {
    // TODO: check a and b lengthes and throw(?) if they are not 4
    word res(4);
    for (int i = 0; i < 4; ++i) {
        res[i] = a[i] ^ b[i];
    }
    return res;
}

word AES::Rcon(int pow) {
    unsigned char RC = 0x01;
    for (int i = 1; i < pow; ++i) {
        RC = xtime(RC);
    }

    word res = {RC, 0x00, 0x00, 0x00};
    return res;
}

unsigned char AES::xtime(unsigned char el) {
    return el >> 7 ? el << 1 ^ 0x1B : el << 1;
}

std::vector<std::vector<unsigned char>> AES::makeState(std::vector<unsigned char> data, int start) {
    std::vector<std::vector<unsigned char>> state;
    if (data.size() <= start) return state;
    for (int i = start; i < start + 4; ++i) {
        std::vector<unsigned char> row = {data[i], data[i + 4], data[i + 8], data[i + 12]};
        state.push_back(row);
    }
    return state;
}

std::vector<unsigned char> AES::unmakeState(std::vector<std::vector<unsigned char>> state) {
    std::vector<unsigned char> data;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            data.push_back(state[j][i]);
        }
    }
    return data;
}

void AES::rorRow(std::vector<unsigned char>& row, int shift) {
    std::vector<unsigned char> temp(row);
    row[0] = temp[(0 + shift) % 4];
    row[1] = temp[(1 + shift) % 4];
    row[2] = temp[(2 + shift) % 4];
    row[3] = temp[(3 + shift) % 4];
}