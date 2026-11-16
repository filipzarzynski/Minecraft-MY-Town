package digital.filip.mytown;

import com.destroystokyo.paper.profile.PlayerProfile;
import io.papermc.paper.command.brigadier.BasicCommand;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.connection.PlayerCommonConnection;
import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.connection.PlayerConnection;
import io.papermc.paper.connection.PlayerLoginConnection;
import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.dialog.DialogResponseView;
import io.papermc.paper.event.connection.PlayerConnectionValidateLoginEvent;
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent;
import io.papermc.paper.event.player.PlayerCustomClickEvent;
import io.papermc.paper.plugin.lifecycle.event.types.LifecycleEvents;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/**
 * Pre-join GUI Gatekeeper for Purpur 26.3.
 * Enforces a shared Server Invite Code on first registration plus salted PBKDF2
 * per-player passwords using Paper's Configuration-Phase Dialog API.
 */
@SuppressWarnings("UnstableApiUsage")
public final class MYTownGatekeeperPlugin extends JavaPlugin implements Listener {

    private static final Key ACTION_SUBMIT = Key.key("mytowngatekeeper:auth/submit");
    private static final Key ACTION_ABORT = Key.key("mytowngatekeeper:auth/abort");
    private static final Pattern VALID_USERNAME = Pattern.compile("^[a-zA-Z0-9_]{3,16}$");
    private static final int PBKDF2_ITERATIONS = 65_536;
    private static final int PBKDF2_KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final int MAX_CONCURRENT_AUTH = 16;
    private static final int MAX_CONCURRENT_AUTH_PER_IP = 2;
    private static final int MAX_LOCKOUT_ENTRIES = 4096;
    private static final int MAX_INVITE_LENGTH = 128;
    private static final long POST_AUTH_SPAWN_TTL_MS = 30_000L;

    private final SecureRandom secureRandom = new SecureRandom();
    private final Object stateLock = new Object();
    private final Semaphore pbkdf2Semaphore = new Semaphore(2);

    private final ConcurrentHashMap<PlayerCommonConnection, AuthSession> pendingAuth =
        new ConcurrentHashMap<>();
    private final Set<String> activeConfiguringUsers = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Long> postAuthSpawningUsers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AccountRecord> accounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LockoutState> ipLockouts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LockoutState> userLockouts = new ConcurrentHashMap<>();

    private volatile String inviteCode;
    private volatile long sessionTtlSeconds;
    private volatile int authTimeoutSeconds;
    private volatile int minPasswordLength;
    private volatile int maxPasswordLength;
    private volatile int maxFailedAttempts;
    private volatile long lockoutSeconds;

    private File accountsFile;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        loadConfigurationSettings();
        this.accountsFile = new File(getDataFolder(), "accounts.yml");
        loadAccounts();

        Bukkit.getPluginManager().registerEvents(this, this);
        registerCommands();

        getLogger().info("MYTownGatekeeper enabled (" + accounts.size() + " registered accounts).");
    }

    @Override
    public void onDisable() {
        for (AuthSession session : pendingAuth.values()) {
            session.future.complete(DialogSubmission.abortedResult());
        }
        pendingAuth.clear();
        activeConfiguringUsers.clear();
        postAuthSpawningUsers.clear();
        saveAccounts();
    }

    private void loadConfigurationSettings() {
        synchronized (stateLock) {
            reloadConfig();
            this.inviteCode = getConfig().getString("invite-code", "CHANGE-ME").trim();
            long ttlHours = Math.max(0L, getConfig().getLong("session-ttl-hours", 24L));
            this.sessionTtlSeconds = ttlHours * 3600L;
            this.authTimeoutSeconds = Math.max(15, getConfig().getInt("auth-timeout-seconds", 90));
            this.minPasswordLength = Math.max(4, getConfig().getInt("min-password-length", 6));
            this.maxPasswordLength = Math.max(this.minPasswordLength, getConfig().getInt("max-password-length", 128));
            this.maxFailedAttempts = Math.max(1, getConfig().getInt("max-failed-attempts", 5));
            long lockMins = Math.max(1L, getConfig().getLong("lockout-minutes", 15L));
            this.lockoutSeconds = lockMins * 60L;

            if ("CHANGE-ME".equals(this.inviteCode) || this.inviteCode.isEmpty() || this.inviteCode.startsWith("CHANGE-ME-")) {
                getLogger().warning("invite-code is set to a placeholder! Rotate it immediately with /gatekeeper setinvite <code>.");
            }
        }
    }

    private void loadAccounts() {
        synchronized (stateLock) {
            accounts.clear();
            if (!accountsFile.exists()) {
                return;
            }
            YamlConfiguration yaml = YamlConfiguration.loadConfiguration(accountsFile);
            ConfigurationSection root = yaml.getConfigurationSection("accounts");
            if (root == null) {
                return;
            }
            for (String key : root.getKeys(false)) {
                ConfigurationSection sec = root.getConfigurationSection(key);
                if (sec == null) {
                    continue;
                }
                String displayName = sec.getString("username", key);
                String saltB64 = sec.getString("salt", "");
                String hashB64 = sec.getString("hash", "");
                String lastIp = sec.getString("last-ip", "");
                long lastLogin = sec.getLong("last-login-epoch", 0L);
                long createdAt = sec.getLong("created-at-epoch", 0L);
                if (!saltB64.isEmpty() && !hashB64.isEmpty()) {
                    accounts.put(key.toLowerCase(Locale.ROOT), new AccountRecord(
                        displayName, saltB64, hashB64, lastIp, lastLogin, createdAt
                    ));
                }
            }
        }
    }

    private void saveAccounts() {
        synchronized (stateLock) {
            if (!getDataFolder().exists() && !getDataFolder().mkdirs()) {
                getLogger().warning("Failed to create plugin data folder.");
                return;
            }
            YamlConfiguration yaml = new YamlConfiguration();
            for (Map.Entry<String, AccountRecord> entry : accounts.entrySet()) {
                String path = "accounts." + entry.getKey();
                AccountRecord rec = entry.getValue();
                yaml.set(path + ".username", rec.displayName);
                yaml.set(path + ".salt", rec.saltBase64);
                yaml.set(path + ".hash", rec.hashBase64);
                yaml.set(path + ".last-ip", rec.lastIp);
                yaml.set(path + ".last-login-epoch", rec.lastLoginEpochSec);
                yaml.set(path + ".created-at-epoch", rec.createdAtEpochSec);
            }
            Path target = accountsFile.toPath();
            Path tmp = target.resolveSibling("accounts.yml.tmp");
            try {
                yaml.save(tmp.toFile());
                try {
                    Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException ex) {
                    Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException ex) {
                getLogger().severe("Failed to persist accounts.yml: " + ex.getMessage());
            }
        }
    }

    private void registerCommands() {
        getLifecycleManager().registerEventHandler(LifecycleEvents.COMMANDS, event ->
            event.registrar().register(
                "gatekeeper",
                "Manage MY-Town Gatekeeper authentication and invite codes",
                new GatekeeperCommand()
            )
        );
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        postAuthSpawningUsers.remove(event.getPlayer().getName().toLowerCase(Locale.ROOT));
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerQuit(PlayerQuitEvent event) {
        postAuthSpawningUsers.remove(event.getPlayer().getName().toLowerCase(Locale.ROOT));
    }

    /**
     * Initial login handshake gate only (ignores post-configuration revalidation).
     */
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onValidateLogin(PlayerConnectionValidateLoginEvent event) {
        if (!event.isAllowed()) {
            return;
        }
        if (!(event.getConnection() instanceof PlayerLoginConnection loginConn)) {
            return;
        }

        String ip = extractIp(loginConn);
        long ipLockSec = getLockoutRemainingSeconds(ipLockouts, ip);
        if (ipLockSec > 0) {
            event.kickMessage(Component.text(
                "Too many failed authentication attempts from your IP. Try again in "
                    + formatDuration(ipLockSec) + ".",
                NamedTextColor.RED
            ));
            return;
        }

        PlayerProfile profile = loginConn.getAuthenticatedProfile();
        if (profile == null) {
            profile = loginConn.getUnsafeProfile();
        }
        String rawName = profile != null ? profile.getName() : null;
        if (rawName == null || !VALID_USERNAME.matcher(rawName).matches()) {
            event.kickMessage(Component.text("Invalid Minecraft username.", NamedTextColor.RED));
            return;
        }

        String userKey = rawName.toLowerCase(Locale.ROOT);
        if (isPlayerOnlineOrTransitioning(rawName, userKey)) {
            getLogger().warning("Rejected duplicate unauthenticated login for active user '" + rawName + "' from " + ip + ".");
            event.kickMessage(Component.text("That player is already logged in.", NamedTextColor.RED));
            return;
        }

        // Allow returning players on valid non-expired IP sessions to proceed even if dialog queue is busy
        if (hasValidIpSession(userKey, ip)) {
            return;
        }

        long pairLockSec = getLockoutRemainingSeconds(userLockouts, pairKey(ip, userKey));
        if (pairLockSec > 0) {
            event.kickMessage(Component.text(
                "Authentication temporarily locked for this account from your IP. Try again in "
                    + formatDuration(pairLockSec) + ".",
                NamedTextColor.RED
            ));
            return;
        }

        if (pendingAuth.size() >= MAX_CONCURRENT_AUTH || countPendingForIp(ip) >= MAX_CONCURRENT_AUTH_PER_IP) {
            event.kickMessage(Component.text(
                "Server authentication queue is busy. Please retry in a few seconds.",
                NamedTextColor.YELLOW
            ));
        }
    }

    /**
     * Configuration-phase pre-world authentication gate (fail-closed).
     */
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPlayerConfigure(AsyncPlayerConnectionConfigureEvent event) {
        PlayerConfigurationConnection conn = event.getConnection();
        String rawUsername = conn.getProfile().getName();
        if (rawUsername == null || !VALID_USERNAME.matcher(rawUsername).matches()) {
            conn.disconnect(Component.text("Invalid Minecraft username.", NamedTextColor.RED));
            return;
        }

        String userKey = rawUsername.toLowerCase(Locale.ROOT);
        String ip = extractIp(conn);

        if (isPlayerOnlineOrTransitioning(rawUsername, userKey) || !activeConfiguringUsers.add(userKey)) {
            conn.disconnect(Component.text("That player is already logged in or authenticating.", NamedTextColor.RED));
            return;
        }

        boolean authenticated = false;
        try {
            long ipLockSec = getLockoutRemainingSeconds(ipLockouts, ip);
            if (ipLockSec > 0) {
                conn.disconnect(Component.text(
                    "Authentication temporarily locked from your IP. Try again in " + formatDuration(ipLockSec) + ".",
                    NamedTextColor.RED
                ));
                return;
            }

            // Absolute 24h IP session check (do not extend lastLoginEpochSec without password entry)
            if (hasValidIpSession(userKey, ip)) {
                markAuthenticated(userKey);
                authenticated = true;
                getLogger().info("Resumed IP session for " + rawUsername + " (" + ip + ").");
                return;
            }

            final String scopedPairKey = pairKey(ip, userKey);
            final long connectionDeadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(authTimeoutSeconds);
            String errorBanner = null;

            while (conn.isConnected()) {
                long currentLock = Math.max(
                    getLockoutRemainingSeconds(ipLockouts, ip),
                    getLockoutRemainingSeconds(userLockouts, scopedPairKey)
                );
                if (currentLock > 0) {
                    conn.disconnect(Component.text(
                        "Too many failed attempts. Locked for " + formatDuration(currentLock) + ".",
                        NamedTextColor.RED
                    ));
                    return;
                }

                if (System.nanoTime() >= connectionDeadlineNanos) {
                    conn.disconnect(Component.text("Authentication timed out. Please reconnect.", NamedTextColor.RED));
                    return;
                }

                if (pendingAuth.size() >= MAX_CONCURRENT_AUTH || countPendingForIp(ip) >= MAX_CONCURRENT_AUTH_PER_IP) {
                    conn.disconnect(Component.text(
                        "Server authentication queue is busy. Please retry in a few seconds.",
                        NamedTextColor.YELLOW
                    ));
                    return;
                }

                AccountRecord existing = accounts.get(userKey);
                boolean isRegistration = (existing == null);

                Dialog dialog = isRegistration
                    ? buildRegistrationDialog(rawUsername, errorBanner)
                    : buildLoginDialog(rawUsername, errorBanner, remainingAttempts(ip, scopedPairKey));

                CompletableFuture<DialogSubmission> future = new CompletableFuture<>();
                AuthSession session = new AuthSession(future, ip, userKey, conn);
                pendingAuth.put(conn, session);
                DialogSubmission submission;
                try {
                    conn.getAudience().showDialog(dialog);
                    submission = awaitSubmission(conn, future, connectionDeadlineNanos);
                } finally {
                    pendingAuth.remove(conn, session);
                }

                if (submission == null) {
                    if (conn.isConnected()) {
                        conn.disconnect(Component.text("Authentication timed out. Please reconnect.", NamedTextColor.RED));
                    }
                    return;
                }
                if (submission.aborted) {
                    if (conn.isConnected()) {
                        conn.disconnect(Component.text("Authentication cancelled.", NamedTextColor.YELLOW));
                    }
                    return;
                }

                if (isRegistration) {
                    String enteredInvite = submission.inviteCode == null ? "" : submission.inviteCode.trim();
                    String pwd = submission.password == null ? "" : submission.password;
                    String pwdConfirm = submission.passwordConfirm == null ? "" : submission.passwordConfirm;

                    if (enteredInvite.isEmpty() || enteredInvite.length() > MAX_INVITE_LENGTH
                        || !constantTimeEquals(enteredInvite, this.inviteCode)) {
                        int left = recordFailure(ip, scopedPairKey);
                        getLogger().warning("Failed invite attempt for " + rawUsername + " from " + ip + " (" + left + " left)");
                        if (left <= 0) {
                            conn.disconnect(Component.text("Too many failed invite attempts. Try again later.", NamedTextColor.RED));
                            return;
                        }
                        errorBanner = "Invalid Server Invite Code (" + left + " attempts remaining).";
                        continue;
                    }

                    if (pwd.length() < minPasswordLength || pwd.length() > maxPasswordLength) {
                        errorBanner = "Personal password must be " + minPasswordLength + "-" + maxPasswordLength + " characters.";
                        continue;
                    }
                    if (!pwd.equals(pwdConfirm)) {
                        errorBanner = "Passwords do not match. Please re-enter them.";
                        continue;
                    }

                    AccountRecord created;
                    try {
                        created = createAccountRecord(rawUsername, pwd, ip);
                    } catch (IllegalArgumentException | IllegalStateException ex) {
                        conn.disconnect(Component.text("Authentication service busy. Please retry.", NamedTextColor.YELLOW));
                        return;
                    }

                    AccountRecord race = accounts.putIfAbsent(userKey, created);
                    if (race != null) {
                        errorBanner = "Account already exists. Please log in with your password.";
                        continue;
                    }
                    clearFailures(ip, scopedPairKey);
                    saveAccounts();
                    markAuthenticated(userKey);
                    authenticated = true;
                    getLogger().info("Registered new account " + rawUsername + " from " + ip + ".");
                    return;
                } else {
                    String pwd = submission.password == null ? "" : submission.password;
                    if (pwd.isEmpty() || pwd.length() > maxPasswordLength) {
                        int left = recordFailure(ip, scopedPairKey);
                        if (left <= 0) {
                            conn.disconnect(Component.text("Too many failed password attempts. Try again later.", NamedTextColor.RED));
                            return;
                        }
                        errorBanner = "Password must be 1-" + maxPasswordLength + " characters (" + left + " attempts remaining).";
                        continue;
                    }

                    boolean validPwd;
                    try {
                        validPwd = verifyPassword(pwd, existing);
                    } catch (IllegalArgumentException ex) {
                        getLogger().warning("Malformed password hash/salt for " + rawUsername + "; failing closed.");
                        conn.disconnect(Component.text("Account credential error. Contact server admin.", NamedTextColor.RED));
                        return;
                    } catch (IllegalStateException busyEx) {
                        conn.disconnect(Component.text("Authentication service busy. Please retry.", NamedTextColor.YELLOW));
                        return;
                    }

                    if (validPwd) {
                        AccountRecord updated = accounts.computeIfPresent(
                            userKey,
                            (k, cur) -> cur.withLogin(ip, Instant.now().getEpochSecond())
                        );
                        if (updated == null) {
                            errorBanner = "Your account was reset. Please re-register with the invite code.";
                            continue;
                        }
                        clearFailures(ip, scopedPairKey);
                        saveAccounts();
                        markAuthenticated(userKey);
                        authenticated = true;
                        getLogger().info("Authenticated " + rawUsername + " from " + ip + ".");
                        return;
                    }

                    int left = recordFailure(ip, scopedPairKey);
                    getLogger().warning("Failed password login for " + rawUsername + " from " + ip + " (" + left + " left)");
                    if (left <= 0) {
                        conn.disconnect(Component.text("Too many failed password attempts. Try again later.", NamedTextColor.RED));
                        return;
                    }
                    errorBanner = "Incorrect personal password (" + left + " attempts remaining).";
                }
            }
        } finally {
            activeConfiguringUsers.remove(userKey);
            if (!authenticated) {
                postAuthSpawningUsers.remove(userKey);
                try {
                    if (conn.isConnected()) {
                        conn.disconnect(Component.text("Authentication incomplete.", NamedTextColor.RED));
                    }
                } catch (Throwable ignored) {
                }
            }
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onCustomClick(PlayerCustomClickEvent event) {
        Key id = event.getIdentifier();
        if (!"mytowngatekeeper".equals(id.namespace())) {
            return;
        }
        AuthSession session = pendingAuth.get(event.getCommonConnection());
        if (session == null) {
            return;
        }
        if (ACTION_ABORT.equals(id)) {
            session.future.complete(DialogSubmission.abortedResult());
            return;
        }
        if (ACTION_SUBMIT.equals(id)) {
            DialogResponseView view = event.getDialogResponseView();
            if (view == null) {
                session.future.complete(DialogSubmission.abortedResult());
                return;
            }
            String invite = view.getText("invite_code");
            String pass = view.getText("password");
            String passConfirm = view.getText("password_confirm");
            session.future.complete(new DialogSubmission(false, invite, pass, passConfirm));
        }
    }

    private DialogSubmission awaitSubmission(
        PlayerConfigurationConnection conn,
        CompletableFuture<DialogSubmission> future,
        long connectionDeadlineNanos
    ) {
        while (conn.isConnected()) {
            long remainingMs = TimeUnit.NANOSECONDS.toMillis(connectionDeadlineNanos - System.nanoTime());
            if (remainingMs <= 0) {
                return null;
            }
            long stepMs = Math.min(remainingMs, 1500L);
            try {
                return future.get(stepMs, TimeUnit.MILLISECONDS);
            } catch (TimeoutException ignored) {
                // Keep checking connection liveness until connectionDeadlineNanos expires.
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return null;
            } catch (ExecutionException ex) {
                return null;
            }
        }
        return null;
    }

    private Dialog buildRegistrationDialog(String username, String errorBanner) {
        List<DialogBody> body = new ArrayList<>();
        body.add(DialogBody.plainMessage(
            Component.text("Welcome, " + username + "! Enter the Server Invite Code and create your personal password to claim this username.", NamedTextColor.GRAY),
            340
        ));
        if (errorBanner != null && !errorBanner.isEmpty()) {
            body.add(DialogBody.plainMessage(
                Component.text(errorBanner, NamedTextColor.RED, TextDecoration.BOLD),
                340
            ));
        }
        return Dialog.create(factory -> factory.empty()
            .base(DialogBase.builder(Component.text("MY-Town Registration", NamedTextColor.GOLD, TextDecoration.BOLD))
                .canCloseWithEscape(false)
                .body(body)
                .inputs(List.of(
                    DialogInput.text("invite_code", Component.text("Server Invite Code", NamedTextColor.AQUA))
                        .width(260)
                        .maxLength(MAX_INVITE_LENGTH)
                        .build(),
                    DialogInput.text("password", Component.text("Create Personal Password (min " + minPasswordLength + " chars)", NamedTextColor.GREEN))
                        .width(260)
                        .maxLength(maxPasswordLength)
                        .build(),
                    DialogInput.text("password_confirm", Component.text("Confirm Personal Password", NamedTextColor.GREEN))
                        .width(260)
                        .maxLength(maxPasswordLength)
                        .build()
                ))
                .build()
            )
            .type(DialogType.confirmation(
                ActionButton.builder(Component.text("Register & Join", NamedTextColor.GREEN, TextDecoration.BOLD))
                    .tooltip(Component.text("Verify invite code and create your server account", NamedTextColor.GRAY))
                    .action(DialogAction.customClick(ACTION_SUBMIT, null))
                    .build(),
                ActionButton.builder(Component.text("Disconnect", NamedTextColor.RED))
                    .tooltip(Component.text("Leave the server", NamedTextColor.GRAY))
                    .action(DialogAction.customClick(ACTION_ABORT, null))
                    .build()
            ))
        );
    }

    private Dialog buildLoginDialog(String username, String errorBanner, int attemptsLeft) {
        List<DialogBody> body = new ArrayList<>();
        body.add(DialogBody.plainMessage(
            Component.text("Welcome back, " + username + ". Enter your personal account password to continue.", NamedTextColor.GRAY),
            340
        ));
        if (errorBanner != null && !errorBanner.isEmpty()) {
            body.add(DialogBody.plainMessage(
                Component.text(errorBanner, NamedTextColor.RED, TextDecoration.BOLD),
                340
            ));
        }
        return Dialog.create(factory -> factory.empty()
            .base(DialogBase.builder(Component.text("MY-Town Login", NamedTextColor.AQUA, TextDecoration.BOLD))
                .canCloseWithEscape(false)
                .body(body)
                .inputs(List.of(
                    DialogInput.text("password", Component.text("Personal Password", NamedTextColor.GREEN))
                        .width(260)
                        .maxLength(maxPasswordLength)
                        .build()
                ))
                .build()
            )
            .type(DialogType.confirmation(
                ActionButton.builder(Component.text("Login", NamedTextColor.GREEN, TextDecoration.BOLD))
                    .tooltip(Component.text(attemptsLeft + " attempts remaining", NamedTextColor.GRAY))
                    .action(DialogAction.customClick(ACTION_SUBMIT, null))
                    .build(),
                ActionButton.builder(Component.text("Disconnect", NamedTextColor.RED))
                    .tooltip(Component.text("Leave the server", NamedTextColor.GRAY))
                    .action(DialogAction.customClick(ACTION_ABORT, null))
                    .build()
            ))
        );
    }

    private AccountRecord createAccountRecord(String username, String password, String ip) {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        byte[] hash = pbkdf2(password, salt);
        long now = Instant.now().getEpochSecond();
        return new AccountRecord(
            username,
            Base64.getEncoder().encodeToString(salt),
            Base64.getEncoder().encodeToString(hash),
            ip,
            now,
            now
        );
    }

    private boolean verifyPassword(String password, AccountRecord record) {
        byte[] salt = Base64.getDecoder().decode(record.saltBase64);
        byte[] expectedHash = Base64.getDecoder().decode(record.hashBase64);
        if (salt.length == 0 || expectedHash.length == 0) {
            throw new IllegalArgumentException("Empty salt or hash in account store");
        }
        byte[] actualHash = pbkdf2(password, salt);
        return MessageDigest.isEqual(expectedHash, actualHash);
    }

    private byte[] pbkdf2(String password, byte[] salt) {
        try {
            if (!pbkdf2Semaphore.tryAcquire(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("PBKDF2 concurrency limit reached");
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("PBKDF2 interrupted", ex);
        }
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BITS);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 unavailable", ex);
        } finally {
            pbkdf2Semaphore.release();
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String extractIp(PlayerConnection conn) {
        InetSocketAddress addr = conn.getClientAddress();
        if (addr == null) {
            return "";
        }
        InetAddress inet = addr.getAddress();
        return inet != null ? inet.getHostAddress() : addr.getHostString();
    }

    private static String pairKey(String ip, String userKey) {
        return (ip == null ? "" : ip) + "|" + userKey;
    }

    private boolean hasValidIpSession(String userKey, String ip) {
        if (sessionTtlSeconds <= 0 || ip == null || ip.isEmpty()) {
            return false;
        }
        AccountRecord existing = accounts.get(userKey);
        if (existing == null || existing.lastLoginEpochSec <= 0) {
            return false;
        }
        long now = Instant.now().getEpochSecond();
        return ip.equals(existing.lastIp) && (now - existing.lastLoginEpochSec) <= sessionTtlSeconds;
    }

    private void markAuthenticated(String userKey) {
        postAuthSpawningUsers.put(userKey, System.currentTimeMillis() + POST_AUTH_SPAWN_TTL_MS);
    }

    private boolean isPostAuthSpawning(String userKey) {
        Long expiresAt = postAuthSpawningUsers.get(userKey);
        if (expiresAt == null) {
            return false;
        }
        if (expiresAt <= System.currentTimeMillis()) {
            postAuthSpawningUsers.remove(userKey, expiresAt);
            return false;
        }
        return true;
    }

    private boolean isPlayerOnlineOrTransitioning(String username, String userKey) {
        if (isPlayerCurrentlyOnline(username) || isPostAuthSpawning(userKey)) {
            return true;
        }
        return false;
    }

    private int countPendingForIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            return 0;
        }
        int count = 0;
        for (AuthSession session : pendingAuth.values()) {
            if (ip.equals(session.ip)) {
                count++;
            }
        }
        return count;
    }

    private static boolean isPlayerCurrentlyOnline(String username) {
        for (Player p : Bukkit.getOnlinePlayers()) {
            if (p.getName().equalsIgnoreCase(username)) {
                return true;
            }
        }
        return false;
    }

    private int remainingAttempts(String ip, String scopedPairKey) {
        int ipFails = getFailureCount(ipLockouts, ip);
        int pairFails = getFailureCount(userLockouts, scopedPairKey);
        return Math.max(0, maxFailedAttempts - Math.max(ipFails, pairFails));
    }

    private int recordFailure(String ip, String scopedPairKey) {
        int ipLeft = incrementFailure(ipLockouts, ip);
        int pairLeft = incrementFailure(userLockouts, scopedPairKey);
        return Math.min(ipLeft, pairLeft);
    }

    private int incrementFailure(ConcurrentHashMap<String, LockoutState> map, String key) {
        if (key == null || key.isEmpty()) {
            return maxFailedAttempts;
        }
        long now = Instant.now().getEpochSecond();
        if (map.size() >= 256) {
            pruneExpiredLockouts(map, now);
        }
        if (!map.containsKey(key) && map.size() >= MAX_LOCKOUT_ENTRIES) {
            evictOldestLockout(map);
        }
        LockoutState updated = map.compute(key, (k, cur) -> {
            if (cur == null
                || (cur.lockedUntilEpochSec > 0 && cur.lockedUntilEpochSec <= now)
                || (cur.lockedUntilEpochSec == 0 && (now - cur.lastFailureEpochSec) >= lockoutSeconds)) {
                int fails = 1;
                long lockUntil = fails >= maxFailedAttempts ? now + lockoutSeconds : 0L;
                return new LockoutState(fails, lockUntil, now);
            }
            int fails = cur.failures + 1;
            long lockUntil = fails >= maxFailedAttempts ? now + lockoutSeconds : cur.lockedUntilEpochSec;
            return new LockoutState(fails, lockUntil, now);
        });
        return Math.max(0, maxFailedAttempts - updated.failures);
    }

    private void pruneExpiredLockouts(ConcurrentHashMap<String, LockoutState> map, long now) {
        map.entrySet().removeIf(e -> {
            LockoutState s = e.getValue();
            return (s.lockedUntilEpochSec > 0 && s.lockedUntilEpochSec <= now)
                || (s.lockedUntilEpochSec == 0 && (now - s.lastFailureEpochSec) >= lockoutSeconds);
        });
    }

    private static void evictOldestLockout(ConcurrentHashMap<String, LockoutState> map) {
        map.entrySet().stream()
            .min(Comparator.comparingLong(e -> e.getValue().lastFailureEpochSec))
            .ifPresent(oldest -> map.remove(oldest.getKey(), oldest.getValue()));
    }

    private int getFailureCount(ConcurrentHashMap<String, LockoutState> map, String key) {
        if (key == null || key.isEmpty()) {
            return 0;
        }
        LockoutState state = map.get(key);
        if (state == null) {
            return 0;
        }
        long now = Instant.now().getEpochSecond();
        if ((state.lockedUntilEpochSec > 0 && state.lockedUntilEpochSec <= now)
            || (state.lockedUntilEpochSec == 0 && (now - state.lastFailureEpochSec) >= lockoutSeconds)) {
            map.remove(key, state);
            return 0;
        }
        return state.failures;
    }

    private long getLockoutRemainingSeconds(ConcurrentHashMap<String, LockoutState> map, String key) {
        if (key == null || key.isEmpty()) {
            return 0L;
        }
        LockoutState state = map.get(key);
        if (state == null || state.lockedUntilEpochSec <= 0) {
            return 0L;
        }
        long now = Instant.now().getEpochSecond();
        long rem = state.lockedUntilEpochSec - now;
        if (rem <= 0) {
            map.remove(key, state);
            return 0L;
        }
        return rem;
    }

    private void clearFailures(String ip, String scopedPairKey) {
        if (ip != null && !ip.isEmpty()) {
            ipLockouts.remove(ip);
        }
        if (scopedPairKey != null && !scopedPairKey.isEmpty()) {
            userLockouts.remove(scopedPairKey);
        }
    }

    private static String formatDuration(long seconds) {
        long mins = seconds / 60;
        long secs = seconds % 60;
        return mins > 0 ? (mins + "m " + secs + "s") : (secs + "s");
    }

    private record AuthSession(
        CompletableFuture<DialogSubmission> future,
        String ip,
        String userKey,
        PlayerConfigurationConnection conn
    ) {
    }

    private record DialogSubmission(boolean aborted, String inviteCode, String password, String passwordConfirm) {
        static DialogSubmission abortedResult() {
            return new DialogSubmission(true, null, null, null);
        }
    }

    private record AccountRecord(
        String displayName,
        String saltBase64,
        String hashBase64,
        String lastIp,
        long lastLoginEpochSec,
        long createdAtEpochSec
    ) {
        AccountRecord withLogin(String ip, long nowEpochSec) {
            return new AccountRecord(displayName, saltBase64, hashBase64, ip, nowEpochSec, createdAtEpochSec);
        }
    }

    private record LockoutState(int failures, long lockedUntilEpochSec, long lastFailureEpochSec) {
    }

    private final class GatekeeperCommand implements BasicCommand {
        @Override
        public boolean canUse(CommandSender sender) {
            return sender instanceof ConsoleCommandSender
                || sender.isOp()
                || sender.hasPermission("mytown.gatekeeper.admin");
        }

        @Override
        public String permission() {
            return "mytown.gatekeeper.admin";
        }

        @Override
        public void execute(CommandSourceStack stack, String[] args) {
            CommandSender sender = stack.getSender();
            if (!canUse(sender)) {
                sender.sendMessage(Component.text("You do not have permission.", NamedTextColor.RED));
                return;
            }
            if (args.length == 0 || "help".equalsIgnoreCase(args[0])) {
                sender.sendMessage(Component.text(
                    "Gatekeeper commands: /gatekeeper status [reveal] | setinvite <code> | resetpassword <user> | clearlockout <ip|user|all> | reload",
                    NamedTextColor.AQUA
                ));
                return;
            }

            switch (args[0].toLowerCase(Locale.ROOT)) {
                case "status" -> {
                    long now = Instant.now().getEpochSecond();
                    long activeLocks = ipLockouts.values().stream().filter(s -> s.lockedUntilEpochSec > now).count()
                        + userLockouts.values().stream().filter(s -> s.lockedUntilEpochSec > now).count();
                    boolean reveal = (sender instanceof ConsoleCommandSender)
                        || (args.length >= 2 && "reveal".equalsIgnoreCase(args[1]));
                    String displayInvite = reveal ? inviteCode : "*** (use RCON or /gatekeeper status reveal)";
                    sender.sendMessage(Component.text(
                        "MYTownGatekeeper Status: registered=" + accounts.size()
                            + ", activeLockouts=" + activeLocks
                            + ", sessionTTLHours=" + (sessionTtlSeconds / 3600L)
                            + ", inviteCode=" + displayInvite,
                        NamedTextColor.GREEN
                    ));
                }
                case "setinvite" -> {
                    if (args.length < 2) {
                        sender.sendMessage(Component.text("Usage: /gatekeeper setinvite <new_code>", NamedTextColor.RED));
                        return;
                    }
                    String newCode = args[1].trim();
                    if (newCode.length() < 4 || newCode.length() > MAX_INVITE_LENGTH) {
                        sender.sendMessage(Component.text("Invite code must be 4-" + MAX_INVITE_LENGTH + " characters.", NamedTextColor.RED));
                        return;
                    }
                    synchronized (stateLock) {
                        inviteCode = newCode;
                        getConfig().set("invite-code", newCode);
                        saveConfig();
                    }
                    sender.sendMessage(Component.text("Updated server invite code.", NamedTextColor.GREEN));
                }
                case "resetpassword" -> {
                    if (args.length < 2) {
                        sender.sendMessage(Component.text("Usage: /gatekeeper resetpassword <username>", NamedTextColor.RED));
                        return;
                    }
                    String targetKey = args[1].toLowerCase(Locale.ROOT);
                    AccountRecord removed = accounts.remove(targetKey);
                    if (removed == null) {
                        sender.sendMessage(Component.text("No registered account found for '" + args[1] + "'.", NamedTextColor.YELLOW));
                        return;
                    }
                    userLockouts.entrySet().removeIf(e -> e.getKey().endsWith("|" + targetKey));
                    postAuthSpawningUsers.remove(targetKey);
                    for (AuthSession s : pendingAuth.values()) {
                        if (targetKey.equals(s.userKey)) {
                            s.future.complete(DialogSubmission.abortedResult());
                        }
                    }
                    saveAccounts();
                    Player online = Bukkit.getPlayerExact(removed.displayName);
                    if (online != null && online.isOnline()) {
                        online.kick(Component.text("Your server password was reset by an admin. Rejoin with the invite code to set a new password.", NamedTextColor.YELLOW));
                    }
                    sender.sendMessage(Component.text("Reset account for " + removed.displayName + ". They must re-register with the invite code.", NamedTextColor.GREEN));
                }
                case "clearlockout" -> {
                    if (args.length < 2) {
                        sender.sendMessage(Component.text("Usage: /gatekeeper clearlockout <ip|username|all>", NamedTextColor.RED));
                        return;
                    }
                    if ("all".equalsIgnoreCase(args[1])) {
                        ipLockouts.clear();
                        userLockouts.clear();
                        sender.sendMessage(Component.text("Cleared all IP and username lockouts.", NamedTextColor.GREEN));
                    } else {
                        String arg = args[1];
                        String argLower = arg.toLowerCase(Locale.ROOT);
                        ipLockouts.remove(arg);
                        userLockouts.entrySet().removeIf(e -> e.getKey().startsWith(arg + "|") || e.getKey().endsWith("|" + argLower));
                        sender.sendMessage(Component.text("Cleared lockout for " + arg + ".", NamedTextColor.GREEN));
                    }
                }
                case "reload" -> {
                    loadConfigurationSettings();
                    sender.sendMessage(Component.text("Reloaded MYTownGatekeeper configuration.", NamedTextColor.GREEN));
                }
                default -> sender.sendMessage(Component.text("Unknown subcommand. Use /gatekeeper status", NamedTextColor.RED));
            }
        }

        @Override
        public Collection<String> suggest(CommandSourceStack stack, String[] args) {
            if (!canUse(stack.getSender())) {
                return List.of();
            }
            if (args.length <= 1) {
                return List.of("status", "setinvite", "resetpassword", "clearlockout", "reload");
            }
            if (args.length == 2 && "resetpassword".equalsIgnoreCase(args[0])) {
                return accounts.values().stream().map(AccountRecord::displayName).toList();
            }
            return List.of();
        }
    }
}
