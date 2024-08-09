package edu.ifmg.camoleze;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class RC5 {
    // Constantes
    private static final int WORD_SIZE = 32; // Tamanho da palavra em bits
    private static final int NUM_ROUNDS = 12; // Número de rodadas
    private static final int KEY_BYTES = 16; // Número de bytes na chave
    private static final int KEY_WORDS = 4; // Número de palavras na chave
    private static final int EXPANDED_KEY_SIZE = 26; // Tamanho da tabela de chaves expandidas
    private static final int P = 0xb7e15163; // Constante mágica P
    private static final int Q = 0x9e3779b9; // Constante mágica Q

    private final int[] expandedKey = new int[EXPANDED_KEY_SIZE]; // Tabela de chaves expandidas
    private final int[] keyWords = new int[KEY_WORDS]; // Palavras da chave

    // Funções de rotação
    private static int rotateLeft(int value, int shift) {
        // Rotaciona os bits de 'value' para a esquerda por 'shift' bits
        return ((value << shift) | (value >>> (WORD_SIZE - shift)));
    }

    private static int rotateRight(int value, int shift) {
        // Rotaciona os bits de 'value' para a direita por 'shift' bits
        return ((value >>> shift) | (value << (WORD_SIZE - shift)));
    }

    // Função de configuração da chave
    public void setupKey(byte[] key) {
        int u = WORD_SIZE / 8; // Número de bytes por palavra
        int tempA, tempB;

        // Inicializa as palavras da chave a partir do array de bytes da chave
        for (int i = KEY_BYTES - 1; i >= 0; i--) {
            keyWords[i / u] = (keyWords[i / u] << 8) + (key[i] & 0xff);
        }

        // Inicializa a tabela de chaves expandidas com a constante P e uma progressão aritmética
        expandedKey[0] = P;
        for (int i = 1; i < EXPANDED_KEY_SIZE; i++) {
            expandedKey[i] = expandedKey[i - 1] + Q;
        }

        // Mistura a chave na tabela de chaves expandidas
        tempA = tempB = 0;
        int indexS = 0; // Índice para a tabela de chaves expandidas
        int indexL = 0; // Índice para as palavras da chave
        // O loop percorre 3 vezes o tamanho da tabela de chaves expandidas
        for (int k = 0; k < 3 * EXPANDED_KEY_SIZE; k++) {
            tempA = expandedKey[indexS] = rotateLeft(expandedKey[indexS] + (tempA + tempB), 3);
            tempB = keyWords[indexL] = rotateLeft(keyWords[indexL] + (tempA + tempB), (tempA + tempB));
            indexS = (indexS + 1) % EXPANDED_KEY_SIZE; // Atualiza o índice da tabela de chaves expandidas
            indexL = (indexL + 1) % KEY_WORDS; // Atualiza o índice das palavras da chave
        }
    }

    // Função de criptografia
    public void encrypt(int[] plaintext, int[] ciphertext) {
        // Inicializa as variáveis temporárias com os valores das palavras do texto plano
        int tempA = plaintext[0] + expandedKey[0];
        int tempB = plaintext[1] + expandedKey[1];

        // Executa o número de rodadas especificado
        for (int i = 1; i <= NUM_ROUNDS; i++) {
            // Aplica a operação XOR e a rotação à esquerda em cada rodada
            tempA = rotateLeft(tempA ^ tempB, tempB) + expandedKey[2 * i];
            tempB = rotateLeft(tempB ^ tempA, tempA) + expandedKey[2 * i + 1];
        }
        // Define o texto cifrado com os valores resultantes
        ciphertext[0] = tempA;
        ciphertext[1] = tempB;
    }

    // Função de descriptografia
    public void decrypt(int[] ciphertext, int[] plaintext) {
        // Inicializa as variáveis temporárias com os valores das palavras do texto cifrado
        int tempB = ciphertext[1];
        int tempA = ciphertext[0];

        // Executa o número de rodadas especificado em ordem inversa
        for (int i = NUM_ROUNDS; i > 0; i--) {
            // Aplica a rotação à direita e a operação XOR para reverter a criptografia
            tempB = rotateRight(tempB - expandedKey[2 * i + 1], tempA) ^ tempA;
            tempA = rotateRight(tempA - expandedKey[2 * i], tempB) ^ tempB;
        }

        // Recupera o texto plano subtraindo as chaves iniciais
        plaintext[0] = tempA - expandedKey[0];
        plaintext[1] = tempB - expandedKey[1];
    }

    public static int[] stringToBlocks(String str) {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        int numBlocks = (bytes.length + 3) / 4; // Arredonda para cima
        int[] blocks = new int[numBlocks];

        for (int i = 0; i < numBlocks; i++) {
            int block = 0;
            for (int j = 0; j < 4 && i * 4 + j < bytes.length; j++) {
                block = (block << 8) | (bytes[i * 4 + j] & 0xFF);
            }
            blocks[i] = block;
        }

        // Padding: Se a string não preencher exatamente os blocos, adicionamos zeros
        if (bytes.length % 4 != 0) {
            blocks[blocks.length - 1] <<= 8 * (4 - bytes.length % 4);
        }

        return blocks;
    }

    public static String blocksToString(int[] blocks) {
        int numBytes = blocks.length * 4;
        byte[] bytes = new byte[numBytes];

        for (int i = 0; i < blocks.length; i++) {
            for (int j = 0; j < 4; j++) {
                bytes[i * 4 + j] = (byte) (blocks[i] >>> (24 - 8 * j));
            }
        }

        // Remover padding: Remove os zeros à esquerda do último bloco
        int i;
        for (i = numBytes - 1; i >= 0 && bytes[i] == 0; i--) ;
        return new String(bytes, 0, i + 1, StandardCharsets.UTF_8);
    }

    // Metodo para converter o ciphertext para bytes
    private static byte[] convertCiphertextToBytes(int[] ciphertext) {
        ByteBuffer buffer = ByteBuffer.allocate(ciphertext.length * 4); // Cada inteiro é 4 bytes
        for (int value : ciphertext) {
            buffer.putInt(value);
        }
        return buffer.array();
    }

    // Metodo para imprimir bytes em formato hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Uso: java RC5 <chave> <texto>");
            System.exit(1);
        }

        if (args[0].length() > 16) {
            System.out.println("A chave deve ser de 16 bytes.");
            System.exit(1);
        }

        String keyString = args[0];
        String plaintextStr = args[1];

        System.out.println("Palavra informada: " + plaintextStr);

        if (args[1].length() > 8) {
            System.out.println("A palavra é muito grande, sera considerado apenas: " + plaintextStr.substring(0, 8));
        }

        RC5 rc5 = new RC5();
        byte[] key = keyString.getBytes();

        // Converter string para blocos
        int[] plaintext = stringToBlocks(plaintextStr);

        // Alocar espaço para o texto cifrado e descriptografado
        int[] ciphertext = new int[plaintext.length];
        int[] decrypted = new int[plaintext.length];
        int[] decryptedErr = new int[plaintext.length];

        // Expandir chave
        rc5.setupKey(key);

        // Criptografar
        rc5.encrypt(plaintext, ciphertext);

        // Descriptografar
        rc5.decrypt(ciphertext, decrypted);

        // Converter blocos de volta para string
        String decryptedStr = blocksToString(decrypted);

        // Imprimir resultados
        System.out.println("Texto cifrado: " + bytesToHex(convertCiphertextToBytes(ciphertext)));
        System.out.println("Texto descriptografado (Chave certa): " + decryptedStr);

        // Expandir chave errada para provar eficacia do algoritimo
        rc5.setupKey(new byte[KEY_BYTES]);
        rc5.decrypt(ciphertext, decryptedErr);
        System.out.println("Texto descriptografado (Chave errada): " + blocksToString(decryptedErr));
    }
}
