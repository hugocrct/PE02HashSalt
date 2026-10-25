import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Scanner;

public class hash {

    // Dades d'un usuari: nom, salt i hash (la contrasenya original NO es guarda)
    record Usuari(String nom, String salt, String hash) {}

    private static final Map<String, Usuari> usuaris = new HashMap<>();
    private static final SecureRandom random = new SecureRandom();

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner sc = new Scanner(System.in);

        String opcio;
        do {
            System.out.println("\n1. Registrar usuari");
            System.out.println("2. Iniciar sessió");
            System.out.println("3. Prova amb salt diferent");
            System.out.println("0. Sortir");
            System.out.print("Opció: ");
            opcio = sc.nextLine().trim();

            switch (opcio) {
                case "1" -> registrar(sc);
                case "2" -> iniciarSessio(sc);
                case "3" -> provaSaltDiferent(sc);
                case "0" -> System.out.println("Adéu!");
                default -> System.out.println("Opció no vàlida.");
            }
        } while (!opcio.equals("0"));

        sc.close(); // una sola vegada, al final
    }

    // ---------- REGISTRE ----------

    public static void registrar(Scanner sc) throws NoSuchAlgorithmException {
        System.out.print("Nom d'usuari: ");
        String nom = sc.nextLine().trim();

        if (nom.isEmpty()) {
            System.out.println("El nom no pot ser buit.");
            return;
        }
        if (usuaris.containsKey(nom)) {
            System.out.println("L'usuari ja existeix.");
            return;
        }

        String password = "";
        while (password.isEmpty()) {
            System.out.print("Contrasenya: ");
            password = sc.nextLine();
        }

        String salt = generarSalt();
        String hash = calcularHash(salt, password);

        usuaris.put(nom, new Usuari(nom, salt, hash));
        System.out.println("Usuari registrat.");
        System.out.println("Salt: " + salt);
        System.out.println("Hash: " + hash);
    }

    // ---------- AUTENTICACIÓ ----------

    public static void iniciarSessio(Scanner sc) throws NoSuchAlgorithmException {
        // 1. Demanar usuari i contrasenya
        System.out.print("Nom d'usuari: ");
        String nom = sc.nextLine().trim();
        System.out.print("Contrasenya: ");
        String password = sc.nextLine();

        // 2 i 3. Comprovar que existeix i recuperar salt + hash
        Usuari usuari = usuaris.get(nom);
        if (usuari == null) {
            System.out.println("Error: usuari o contrasenya incorrectes.");
            return;
        }

        // 4. Hash de la contrasenya introduïda amb la salt guardada
        String hashCalculat = calcularHash(usuari.salt(), password);

        // 5 i 6. Comparar i permetre accés només si coincideixen
        boolean correcte = MessageDigest.isEqual(
                hashCalculat.getBytes(StandardCharsets.UTF_8),
                usuari.hash().getBytes(StandardCharsets.UTF_8));

        if (correcte) {
            System.out.println("Accés concedit. Benvingut/da, " + usuari.nom() + "!");
        } else {
            System.out.println("Error: usuari o contrasenya incorrectes.");
        }
    }

    // ---------- PROVA AMB SALT DIFERENT ----------

    public static void provaSaltDiferent(Scanner sc) throws NoSuchAlgorithmException {
        System.out.print("Nom d'usuari: ");
        String nom = sc.nextLine().trim();

        Usuari usuari = usuaris.get(nom);
        if (usuari == null) {
            System.out.println("L'usuari no existeix.");
            return;
        }

        System.out.print("Contrasenya correcta de l'usuari: ");
        String password = sc.nextLine();

        String saltDiferent = generarSalt();

        String hashAmbSaltGuardada = calcularHash(usuari.salt(), password);
        String hashAmbSaltDiferent = calcularHash(saltDiferent, password);

        System.out.println("\nHash guardat:            " + usuari.hash());

        System.out.println("\nSalt guardada:           " + usuari.salt());
        System.out.println("Hash amb salt guardada:  " + hashAmbSaltGuardada);
        System.out.println("Coincideix? " + hashAmbSaltGuardada.equals(usuari.hash()));

        System.out.println("\nSalt diferent:           " + saltDiferent);
        System.out.println("Hash amb salt diferent:  " + hashAmbSaltDiferent);
        System.out.println("Coincideix? " + hashAmbSaltDiferent.equals(usuari.hash()));
    }

    // ---------- UTILITATS ----------

    // Salt aleatòria de 16 bytes, diferent a cada crida
    public static String generarSalt() {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return HexFormat.of().withUpperCase().formatHex(salt);
    }

    // Hash SHA-512 de (salt + contrasenya)
    public static String calcularHash(String salt, String password)
            throws NoSuchAlgorithmException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        sha512.update(HexFormat.of().parseHex(salt));
        sha512.update(password.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().withUpperCase().formatHex(sha512.digest());
    }
}