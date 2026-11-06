require('dotenv').config();
const fs = require('fs');
const path = require('path');
const {
    Client, GatewayIntentBits, PermissionsBitField, AuditLogEvent,
    EmbedBuilder, SlashCommandBuilder, REST, Routes, ChannelType,
} = require('discord.js');

// ============================================================
// CONFIG
// ============================================================
const CONFIG = {
    LOG_CHANNEL_ID:    process.env.LOG_CHANNEL_ID    || '',
    EMERGENCY_ROLE_ID: process.env.EMERGENCY_ROLE_ID || '',
    AUTOROLE_ID:       process.env.AUTOROLE_ID       || '',
    PUNISHMENT:        process.env.PUNISHMENT        || 'ban', // ban | kick | strip

    ABSOLUTE_IMMUNE: new Set(
        (process.env.ABSOLUTE_IMMUNE || '').split(',').filter(Boolean)
    ),
    ENV_WHITELISTED_USERS: new Set(
        (process.env.WHITELISTED_USERS || '').split(',').filter(Boolean)
    ),

    RATE_LIMITS: {
        channelDelete: { limit: 2, window: 10000 },
        roleDelete:    { limit: 2, window: 10000 },
        memberBan:     { limit: 3, window: 15000 },
        memberKick:    { limit: 3, window: 15000 },
        webhookCreate: { limit: 2, window: 10000 },
        botAdd:        { limit: 1, window: 60000 },
        channelCreate: { limit: 5, window: 10000 },
    },

    WEIGHTS: {
        roleDangerousUpdate: 5,
        botAdd: 5,
        channelDelete: 4,
        roleDelete: 4,
        guildUpdate: 4,
        memberBan: 3,
        webhookCreate: 3,
        memberKick: 2,
        channelCreate: 1,
        roleCreate: 1,
        emojiDelete: 1,
    },
    SLOW_BURN_THRESHOLD: 30,
    SLOW_BURN_WINDOW: 3600000,
};

// ============================================================
// FEATURES REGISTRY
// ============================================================
const FEATURES = {
    antinuke:          { label: 'Anti-Nuke Core',          default: true  },
    ghostDetection:    { label: 'Ghost Event Detection',   default: true  },
    slowBurn:          { label: 'Slow-Burn Scoring',       default: true  },
    webhookProtection: { label: 'Webhook Nuke Protection', default: true  },
    antiBot:           { label: 'Anti-Bot / Token Spam',   default: true  },
    antiBetray:        { label: 'Anti-Betray Whitelist',   default: true  },
    emergencyMode:     { label: 'Auto Emergency Mode',     default: true  },
    autoRole:          { label: 'AutoRole',                default: false },
    antiEveryone:      { label: 'Anti @everyone/Here',     default: true  },
    antiChannelSpam:   { label: 'Anti Channel Spam',       default: true  },
};

// ============================================================
// PERSISTENCE (settings.json)
// ============================================================
const SETTINGS_FILE = process.env.SETTINGS_PATH || path.join(__dirname, 'settings.json');
let cache = {};

function loadSettings() {
    try {
        if (fs.existsSync(SETTINGS_FILE)) {
            cache = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
        }
    } catch (e) {
        console.error('[settings] load failed:', e);
        cache = {};
    }
}

function saveSettings() {
    try {
        fs.writeFileSync(SETTINGS_FILE, JSON.stringify(cache, null, 2));
    } catch (e) {
        console.error('[settings] save failed:', e);
    }
}

function getGuild(guildId) {
    if (!cache[guildId]) cache[guildId] = {};
    const g = cache[guildId];
    for (const key of Object.keys(FEATURES)) {
        if (typeof g[key] !== 'boolean') g[key] = FEATURES[key].default;
    }
    if (!Array.isArray(g.whitelist)) g.whitelist = [];
    if (!Array.isArray(g.whitelistRoles)) g.whitelistRoles = [];
    return g;
}

function isEnabled(guildId, feature) {
    if (!FEATURES[feature]) return false;
    return getGuild(guildId)[feature] === true;
}

function toggleFeature(guildId, feature) {
    if (!FEATURES[feature]) return null;
    const g = getGuild(guildId);
    g[feature] = !g[feature];
    saveSettings();
    return g[feature];
}

function panicDisableAll(guildId) {
    const g = getGuild(guildId);
    for (const key of Object.keys(FEATURES)) g[key] = false;
    saveSettings();
    return g;
}

// ---------- USER WHITELIST ----------
function getWhitelist(guildId) {
    return getGuild(guildId).whitelist;
}

function addWhitelist(guildId, userId) {
    const wl = getWhitelist(guildId);
    if (!wl.includes(userId)) {
        wl.push(userId);
        saveSettings();
        return true;
    }
    return false;
}

function removeWhitelist(guildId, userId) {
    const g = getGuild(guildId);
    const before = g.whitelist.length;
    g.whitelist = g.whitelist.filter(id => id !== userId);
    if (g.whitelist.length < before) {
        saveSettings();
        return true;
    }
    return false;
}

// ---------- ROLE WHITELIST ----------
function getWhitelistRoles(guildId) {
    return getGuild(guildId).whitelistRoles;
}

function addWhitelistRole(guildId, roleId) {
    const rl = getWhitelistRoles(guildId);
    if (!rl.includes(roleId)) {
        rl.push(roleId);
        saveSettings();
        return true;
    }
    return false;
}

function removeWhitelistRole(guildId, roleId) {
    const g = getGuild(guildId);
    const before = g.whitelistRoles.length;
    g.whitelistRoles = g.whitelistRoles.filter(id => id !== roleId);
    if (g.whitelistRoles.length < before) {
        saveSettings();
        return true;
    }
    return false;
}

// ---------- UNIFIED CHECK ----------
// A user is whitelisted if:
//   1. Their ID is in the env WHITELISTED_USERS list, OR
//   2. Their ID is in the guild's /whitelist list, OR
//   3. They have a role that is in the guild's /whitelist-roles list
function isWhitelisted(guild, userId) {
    if (CONFIG.ENV_WHITELISTED_USERS.has(userId)) return true;
    if (getWhitelist(guild.id).includes(userId)) return true;

    const member = guild.members.cache.get(userId);
    if (member) {
        const roles = getWhitelistRoles(guild.id);
        if (roles.length && member.roles.cache.some(r => roles.includes(r.id))) {
            return true;
        }
    }
    return false;
}

loadSettings();

// ============================================================
// IN-MEMORY STORES
// ============================================================
const rateLimitMap = new Map();
const slowBurnMap = new Map();
const ghostEventMap = new Map();

// ============================================================
// HELPERS
// ============================================================
async function getExecutor(guild, type, targetId) {
    try {
        const logs = await guild.fetchAuditLogs({ limit: 1, type });
        const entry = logs.entries.first();
        if (!entry) return null;
        if (entry.targetId === targetId && (Date.now() - entry.createdTimestamp) < 5000) {
            return entry.executor;
        }
    } catch {}
    return null;
}

function isRateLimited(guildId, userId, actionType) {
    const config = CONFIG.RATE_LIMITS[actionType];
    if (!config) return false;
    const key = `${guildId}-${userId}-${actionType}`;
    const now = Date.now();
    if (!rateLimitMap.has(key)) rateLimitMap.set(key, []);
    const ts = rateLimitMap.get(key).filter(t => now - t < config.window);
    ts.push(now);
    rateLimitMap.set(key, ts);
    return ts.length > config.limit;
}

function checkSlowBurn(guildId, userId, actionType) {
    const weight = CONFIG.WEIGHTS[actionType];
    if (!weight) return false;
    const key = `${guildId}-${userId}`;
    const now = Date.now();
    if (!slowBurnMap.has(key)) slowBurnMap.set(key, []);
    const records = slowBurnMap.get(key).filter(r => now - r.timestamp < CONFIG.SLOW_BURN_WINDOW);
    records.push({ timestamp: now, weight });
    slowBurnMap.set(key, records);
    return records.reduce((s, r) => s + r.weight, 0) >= CONFIG.SLOW_BURN_THRESHOLD;
}

function resetSlowBurn(guildId, userId) {
    slowBurnMap.delete(`${guildId}-${userId}`);
}

async function detectGhost(guild, expectedType, targetId) {
    if (!isEnabled(guild.id, 'ghostDetection')) return false;
    const executor = await getExecutor(guild, expectedType, targetId);
    if (executor) return false;

    const now = Date.now();
    const gid = guild.id;
    if (!ghostEventMap.has(gid)) ghostEventMap.set(gid, []);
    const events = ghostEventMap.get(gid).filter(t => now - t < 15000);
    events.push(now);
    ghostEventMap.set(gid, events);

    if (events.length >= 3 && isEnabled(gid, 'emergencyMode')) {
        await triggerEmergencyMode(guild, 'Ghost Event Nuke (Token Bypass)');
        ghostEventMap.set(gid, []);
    }
    return true;
}

async function logAction(guild, member, reason, isBetrayal = false) {
    const channel = guild.channels.cache.get(CONFIG.LOG_CHANNEL_ID);
    if (!channel) return;
    const embed = new EmbedBuilder()
        .setColor(isBetrayal ? 0xFF0000 : 0xFFA500)
        .setTitle(isBetrayal ? '🚨 Betrayal Detected & Banned' : '🪓 AxeSecurity Triggered')
        .setDescription(`**User:** ${member.user.tag} (${member.id})\n**Reason:** ${reason}`)
        .setTimestamp();
    await channel.send({ embeds: [embed] }).catch(() => {});
}

async function punishUser(guild, userId, reason, isBetrayal = false) {
    try {
        const member = await guild.members.fetch(userId).catch(() => null);
        if (!member) return;
        if (member.id === guild.ownerId || member.id === client.user.id) return;
        if (CONFIG.ABSOLUTE_IMMUNE.has(member.id)) return;

        // Anti-betray: strip whitelist privilege AND role whitelist membership
        if (isBetrayal) {
            removeWhitelist(guild.id, member.id);
            // Also remove any whitelisted roles this user has
            const wlRoles = getWhitelistRoles(guild.id);
            const toRemove = member.roles.cache.filter(r => wlRoles.includes(r.id));
            if (toRemove.size > 0) {
                await member.roles.remove(toRemove, '[AxeSecurity] Betrayal — removing whitelist roles').catch(() => {});
            }
        }

        if (CONFIG.PUNISHMENT === 'ban') {
            await member.ban({ reason: `[AxeSecurity] ${reason}` });
        } else if (CONFIG.PUNISHMENT === 'kick') {
            await member.kick(`[AxeSecurity] ${reason}`);
        } else {
            await member.roles.set([], `[AxeSecurity] ${reason}`);
        }

        console.log(`[PUNISHED] ${member.user.tag} — ${reason}`);
        await logAction(guild, member, reason, isBetrayal);
    } catch (err) {
        console.error('[punish] failed:', err);
    }
}

async function triggerEmergencyMode(guild, reason) {
    try {
        console.log(`[EMERGENCY] Locking down ${guild.name}`);
        guild.channels.cache.forEach(async (channel) => {
            if (channel.type === ChannelType.GuildText || channel.type === ChannelType.GuildAnnouncement) {
                await channel.permissionOverwrites.edit(guild.roles.everyone, {
                    SendMessages: false,
                }).catch(() => {});
            }
        });
        const logChannel = guild.channels.cache.get(CONFIG.LOG_CHANNEL_ID);
        if (logChannel) {
            const embed = new EmbedBuilder()
                .setColor(0xFF0000)
                .setTitle('🚨 EMERGENCY LOCKDOWN ACTIVATED')
                .setDescription(`**Reason:** ${reason}\nPlease review immediately.`)
                .setTimestamp();
            await logChannel.send({ embeds: [embed] }).catch(() => {});
            if (CONFIG.EMERGENCY_ROLE_ID) {
                await logChannel.send(`<@&${CONFIG.EMERGENCY_ROLE_ID}>`).catch(() => {});
            }
        }
    } catch (err) {
        console.error('[emergency] failed:', err);
    }
}

// ============================================================
// CLIENT
// ============================================================
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildModeration,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.GuildWebhooks,
    ],
});

// ============================================================
// SLASH COMMANDS
// ============================================================
const commandDefs = [
    new SlashCommandBuilder()
        .setName('toggle')
        .setDescription('Enable or disable a protection feature')
        .addStringOption(o => o
            .setName('feature').setDescription('Which feature').setRequired(true)
            .addChoices(...Object.entries(FEATURES).map(([k, v]) => ({ name: v.label, value: k }))))
        .setDefaultMemberPermissions(PermissionsBitField.Flags.Administrator),

    new SlashCommandBuilder()
        .setName('features')
        .setDescription('Show all feature states')
        .setDefaultMemberPermissions(PermissionsBitField.Flags.Administrator),

    new SlashCommandBuilder()
        .setName('panic')
        .setDescription('Disable ALL protection features (emergency)')
        .setDefaultMemberPermissions(PermissionsBitField.Flags.Administrator),

    new SlashCommandBuilder()
        .setName('whitelist')
        .setDescription('Manage the user whitelist')
        .setDefaultMemberPermissions(PermissionsBitField.Flags.Administrator)
        .addSubcommand(sub => sub
            .setName('add').setDescription('Add a user to the whitelist')
            .addUserOption(o => o.setName('user').setDescription('User to whitelist').setRequired(true)))
        .addSubcommand(sub => sub
            .setName('remove').setDescription('Remove a user from the whitelist')
            .addUserOption(o => o.setName('user').setDescription('User to remove').setRequired(true)))
        .addSubcommand(sub => sub
            .setName('list').setDescription('Show all whitelisted users')),

    new SlashCommandBuilder()
        .setName('whitelist-roles')
        .setDescription('Manage the role whitelist (immunity for every member with that role)')
        .setDefaultMemberPermissions(PermissionsBitField.Flags.Administrator)
        .addSubcommand(sub => sub
            .setName('add').setDescription('Add a role to the whitelist')
            .addRoleOption(o => o.setName('role').setDescription('Role to whitelist').setRequired(true)))
        .addSubcommand(sub => sub
            .setName('remove').setDescription('Remove a role from the whitelist')
            .addRoleOption(o => o.setName('role').setDescription('Role to remove').setRequired(true)))
        .addSubcommand(sub => sub
            .setName('list').setDescription('Show all whitelisted roles')),
];

// ============================================================
// READY
// ============================================================
client.once('ready', async () => {
    console.log(`🪓 AxeSecurity ready: ${client.user.tag}`);
    client.user.setActivity('for nukes 🛡️', { type: 3 });

    try {
        const rest = new REST({ version: '10' }).setToken(process.env.TOKEN);
        await rest.put(Routes.applicationCommands(client.user.id), {
            body: commandDefs.map(c => c.toJSON()),
        });
        console.log('✅ Slash commands registered.');
    } catch (e) {
        console.error('Failed to register commands:', e);
    }
});

// ============================================================
// INTERACTIONS
// ============================================================
client.on('interactionCreate', async (interaction) => {
    if (!interaction.isChatInputCommand()) return;
    const guild = interaction.guild;
    if (!guild) return;
    if (!interaction.member.permissions.has(PermissionsBitField.Flags.Administrator)) {
        return interaction.reply({ content: '❌ Administrator only.', ephemeral: true });
    }

    // ---------- /toggle ----------
    if (interaction.commandName === 'toggle') {
        const feature = interaction.options.getString('feature');
        const state = toggleFeature(guild.id, feature);
        return interaction.reply({
            embeds: [new EmbedBuilder()
                .setColor(state ? 0x00FF00 : 0xFF0000)
                .setTitle(`${state ? '✅ Enabled' : '❌ Disabled'}: ${FEATURES[feature].label}`)
                .setTimestamp()],
            ephemeral: true,
        });
    }

    // ---------- /features ----------
    if (interaction.commandName === 'features') {
        const g = getGuild(guild.id);
        const lines = Object.entries(FEATURES).map(([k, m]) =>
            `${g[k] ? '🟢' : '🔴'} **${m.label}** \`(${k})\``);
        return interaction.reply({
            embeds: [new EmbedBuilder()
                .setColor(0x5865F2)
                .setTitle('🪓 AxeSecurity — Feature Status')
                .setDescription(lines.join('\n'))
                .setFooter({ text: `Guild: ${guild.name}` })
                .setTimestamp()],
            ephemeral: true,
        });
    }

    // ---------- /panic ----------
    if (interaction.commandName === 'panic') {
        panicDisableAll(guild.id);
        return interaction.reply({
            embeds: [new EmbedBuilder()
                .setColor(0xFF0000)
                .setTitle('🚨 PANIC: All features disabled')
                .setDescription('Every protection is now OFF. Re-enable with `/toggle` when safe.')],
            ephemeral: true,
        });
    }

    // ---------- /whitelist ----------
    if (interaction.commandName === 'whitelist') {
        const sub = interaction.options.getSubcommand();

        if (sub === 'add') {
            const user = interaction.options.getUser('user');
            if (user.id === guild.ownerId) {
                return interaction.reply({
                    content: 'ℹ️ The server owner is always immune, no need to whitelist.',
                    ephemeral: true,
                });
            }
            const added = addWhitelist(guild.id, user.id);
            return interaction.reply({
                embeds: [new EmbedBuilder()
                    .setColor(added ? 0x00FF00 : 0xFFA500)
                    .setTitle(added ? '✅ Added to whitelist' : 'ℹ️ Already whitelisted')
                    .setDescription(`**User:** ${user.tag} (\`${user.id}\`)`)
                    .setTimestamp()],
                ephemeral: true,
            });
        }

        if (sub === 'remove') {
            const user = interaction.options.getUser('user');
            if (CONFIG.ENV_WHITELISTED_USERS.has(user.id)) {
                return interaction.reply({
                    content: `⚠️ **${user.tag}** is in the permanent env whitelist (\`WHITELISTED_USERS\`). Remove them from Render env vars and redeploy.`,
                    ephemeral: true,
                });
            }
            const removed = removeWhitelist(guild.id, user.id);
            return interaction.reply({
                embeds: [new EmbedBuilder()
                    .setColor(removed ? 0x00FF00 : 0xFFA500)
                    .setTitle(removed ? '✅ Removed from whitelist' : 'ℹ️ Not whitelisted')
                    .setDescription(`**User:** ${user.tag} (\`${user.id}\`)`)
                    .setTimestamp()],
                ephemeral: true,
            });
        }

        if (sub === 'list') {
            const wl = getWhitelist(guild.id);
            const envWl = [...CONFIG.ENV_WHITELISTED_USERS];
            const all = [...new Set([...envWl, ...wl])];

            if (all.length === 0) {
                return interaction.reply({ content: '📋 Whitelist is empty.', ephemeral: true });
            }

            const lines = await Promise.all(all.map(async id => {
                const user = await client.users.fetch(id).catch(() => null);
                const tag = user ? `**${user.tag}**` : '`unknown`';
                const source = envWl.includes(id) ? ' *(env)*' : '';
                return `• ${tag} (\`${id}\`)${source}`;
            }));

            return interaction.reply({
                embeds: [new EmbedBuilder()
                    .setColor(0x5865F2)
                    .setTitle(`📋 User Whitelist — ${all.length} user(s)`)
                    .setDescription(lines.join('\n'))
                    .setTimestamp()],
                ephemeral: true,
            });
        }
    }

    // ---------- /whitelist-roles ----------
    if (interaction.commandName === 'whitelist-roles') {
        const sub = interaction.options.getSubcommand();

        if (sub === 'add') {
            const role = interaction.options.getRole('role');
            if (role.id === guild.roles.everyone.id) {
                return interaction.reply({
                    content: '❌ Cannot whitelist @everyone — that would whitelist every member.',
                    ephemeral: true,
                });
            }
            if (role.managed) {
                return interaction.reply({
                    content: `ℹ️ **${role.name}** is a managed role (bot/integration). It will still work as a whitelist trigger, but you can't manually assign it. Adding anyway.`,
                    ephemeral: true,
                }).then(() => {});
            }
            const added = addWhitelistRole(guild.id, role.id);
            return interaction.reply({
                embeds: [new EmbedBuilder()
                    .setColor(added ? 0x00FF00 : 0xFFA500)
                    .setTitle(added ? '✅ Role added to whitelist' : 'ℹ️ Role already whitelisted')
                    .setDescription(`**Role:** ${role.name} (\`${role.id}\`)\nEvery member with this role is now immune.`)
                    .setTimestamp()],
                ephemeral: true,
            });
        }

        if (sub === 'remove') {
            const role = interaction.options.getRole('role');
            const removed = removeWhitelistRole(guild.id, role.id);
            return interaction.reply({
                embeds: [new EmbedBuilder()
                    .setColor(removed ? 0x00FF00 : 0xFFA500)
                    .setTitle(removed ? '✅ Role removed from whitelist' : 'ℹ️ Role not whitelisted')
                    .setDescription(`**Role:** ${role.name} (\`${role.id}\`)`)
                    .setTimestamp()],
                ephemeral: true,
            });
        }

        if (sub === 'list') {
            const roles = getWhitelistRoles(guild.id);
            if (roles.length === 0) {
                return interaction.reply({ content: '📋 Role whitelist is empty.', ephemeral: true });
            }

            const lines = roles.map(id => {
                const role = guild.roles.cache.get(id);
                return role
                    ? `• **${role.name}** (\`${id}\`) — ${role.members.size} member(s)`
                    : `• \`${id}\` (deleted role)`;
            });

            return interaction.reply({
                embeds: [new EmbedBuilder()
                    .setColor(0x5865F2)
                    .setTitle(`📋 Role Whitelist — ${roles.length} role(s)`)
                    .setDescription(lines.join('\n'))
                    .setTimestamp()],
                ephemeral: true,
            });
        }
    }
});

// ============================================================
// ANTI-NUKE EVENTS
// ============================================================

client.on('channelDelete', async (channel) => {
    if (!channel.guild) return;
    const guild = channel.guild;
    if (!isEnabled(guild.id, 'antinuke')) return;
    if (await detectGhost(guild, AuditLogEvent.ChannelDelete, channel.id)) return;

    const executor = await getExecutor(guild, AuditLogEvent.ChannelDelete, channel.id);
    if (!executor || CONFIG.ABSOLUTE_IMMUNE.has(executor.id)) return;

    const whitelisted = isWhitelisted(guild, executor.id);

    if (isEnabled(guild.id, 'antiBetray') && whitelisted
        && isRateLimited(guild.id, executor.id, 'channelDelete')) {
        return punishUser(guild, executor.id, 'Betrayal: Mass Channel Deletion', true);
    }
    if (!whitelisted && isRateLimited(guild.id, executor.id, 'channelDelete')) {
        await punishUser(guild, executor.id, 'Mass Channel Deletion');
    }
    if (isEnabled(guild.id, 'slowBurn') && checkSlowBurn(guild.id, executor.id, 'channelDelete')) {
        await punishUser(guild, executor.id, 'Slow-Burn Nuke (Score Threshold)');
        resetSlowBurn(guild.id, executor.id);
    }
});

client.on('roleDelete', async (role) => {
    const guild = role.guild;
    if (!isEnabled(guild.id, 'antinuke')) return;
    if (await detectGhost(guild, AuditLogEvent.RoleDelete, role.id)) return;

    const executor = await getExecutor(guild, AuditLogEvent.RoleDelete, role.id);
    if (!executor || CONFIG.ABSOLUTE_IMMUNE.has(executor.id)) return;

    const whitelisted = isWhitelisted(guild, executor.id);
    if (isEnabled(guild.id, 'antiBetray') && whitelisted
        && isRateLimited(guild.id, executor.id, 'roleDelete')) {
        return punishUser(guild, executor.id, 'Betrayal: Mass Role Deletion', true);
    }
    if (!whitelisted && isRateLimited(guild.id, executor.id, 'roleDelete')) {
        await punishUser(guild, executor.id, 'Mass Role Deletion');
    }
    if (isEnabled(guild.id, 'slowBurn') && checkSlowBurn(guild.id, executor.id, 'roleDelete')) {
        await punishUser(guild, executor.id, 'Slow-Burn Nuke (Score Threshold)');
        resetSlowBurn(guild.id, executor.id);
    }
});

client.on('roleUpdate', async (oldRole, newRole) => {
    const guild = newRole.guild;
    if (!isEnabled(guild.id, 'antinuke')) return;

    const dangerous = [
        PermissionsBitField.Flags.Administrator,
        PermissionsBitField.Flags.ManageGuild,
        PermissionsBitField.Flags.ManageRoles,
        PermissionsBitField.Flags.BanMembers,
        PermissionsBitField.Flags.KickMembers,
        PermissionsBitField.Flags.ManageWebhooks,
    ];
    const gained = dangerous.some(p =>
        !oldRole.permissions.has(p) && newRole.permissions.has(p));
    if (!gained) return;

    const executor = await getExecutor(guild, AuditLogEvent.RoleUpdate, newRole.id);
    if (!executor || CONFIG.ABSOLUTE_IMMUNE.has(executor.id)) return;
    if (executor.id === guild.ownerId) return;

    await newRole.setPermissions(oldRole.permissions,
        '[AxeSecurity] Reverting dangerous permissions').catch(() => {});

    const whitelisted = isWhitelisted(guild, executor.id);
    await punishUser(guild, executor.id,
        whitelisted ? 'Betrayal: Granting Dangerous Permissions' : 'Granting Dangerous Permissions',
        whitelisted);
});

client.on('guildBanAdd', async (ban) => {
    const guild = ban.guild;
    if (!isEnabled(guild.id, 'antinuke')) return;

    const executor = await getExecutor(guild, AuditLogEvent.MemberBanAdd, ban.user.id);
    if (!executor || CONFIG.ABSOLUTE_IMMUNE.has(executor.id)) return;

    const whitelisted = isWhitelisted(guild, executor.id);
    if (isEnabled(guild.id, 'antiBetray') && whitelisted
        && isRateLimited(guild.id, executor.id, 'memberBan')) {
        return punishUser(guild, executor.id, 'Betrayal: Mass Ban', true);
    }
    if (!whitelisted && isRateLimited(guild.id, executor.id, 'memberBan')) {
        await punishUser(guild, executor.id, 'Mass Ban');
    }
    if (isEnabled(guild.id, 'slowBurn') && checkSlowBurn(guild.id, executor.id, 'memberBan')) {
        await punishUser(guild, executor.id, 'Slow-Burn Nuke (Score Threshold)');
        resetSlowBurn(guild.id, executor.id);
    }
});

client.on('guildMemberAdd', async (member) => {
    const guild = member.guild;

    if (!member.user.bot && isEnabled(guild.id, 'autoRole')) {
        const role = guild.roles.cache.get(CONFIG.AUTOROLE_ID);
        if (role) await member.roles.add(role).catch(() => {});
    }

    if (!member.user.bot) return;
    if (!isEnabled(guild.id, 'antiBot')) return;

    const executor = await getExecutor(guild, AuditLogEvent.BotAdd, member.id);
    if (!executor || CONFIG.ABSOLUTE_IMMUNE.has(executor.id)) return;
    if (executor.id === guild.ownerId) return;

    const whitelisted = isWhitelisted(guild, executor.id);
    await punishUser(guild, executor.id,
        whitelisted ? 'Betrayal: Inviting Unauthorized Bot' : 'Unauthorized Bot Addition',
        whitelisted);
    await member.kick('[AxeSecurity] Unauthorized bot').catch(() => {});
});

client.on('messageCreate', async (message) => {
    if (!message.guild || message.author.bot) return;
    if (!isEnabled(message.guild.id, 'antiEveryone')) return;

    if (message.mentions.everyone) {
        const m = message.member;
        if (!m || !m.permissions.has(PermissionsBitField.Flags.Administrator)) {
            await message.delete().catch(() => {});
            const warn = await message.channel.send(
                `⚠️ ${message.author}, you are not allowed to ping @everyone here.`
            ).catch(() => null);
            setTimeout(() => warn?.delete().catch(() => {}), 5000);
        }
    }
});

client.on('channelCreate', async (channel) => {
    if (!channel.guild) return;
    const guild = channel.guild;
    if (!isEnabled(guild.id, 'antiChannelSpam')) return;

    const executor = await getExecutor(guild, AuditLogEvent.ChannelCreate, channel.id);
    if (!executor || CONFIG.ABSOLUTE_IMMUNE.has(executor.id)) return;

    if (isRateLimited(guild.id, executor.id, 'channelCreate')) {
        await punishUser(guild, executor.id, 'Channel Spam');
        await channel.delete('[AxeSecurity] Channel spam cleanup').catch(() => {});
    }
});

client.on('webhookUpdate', async (channel) => {
    const guild = channel.guild;
    if (!guild) return;
    if (!isEnabled(guild.id, 'webhookProtection')) return;

    const webhooks = await channel.fetchWebhooks().catch(() => null);
    if (!webhooks) return;

    for (const webhook of webhooks.values()) {
        const executor = await getExecutor(guild, AuditLogEvent.WebhookCreate, webhook.id);
        if (!executor || CONFIG.ABSOLUTE_IMMUNE.has(executor.id)) continue;

        const whitelisted = isWhitelisted(guild, executor.id);
        await punishUser(guild, executor.id,
            whitelisted ? 'Betrayal: Creating Webhook' : 'Unauthorized Webhook Creation',
            whitelisted);
        await webhook.delete('[AxeSecurity] Suspicious webhook').catch(() => {});
    }
});

// ============================================================
// LOGIN
// ============================================================
client.login(process.env.TOKEN);
