import discord
import re
import json
import secrets
import string
import math
from discord.ext import commands
from urllib.parse import urlparse

# Set up the bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Expanded Whitelist of trusted domains
whitelisted_domains = [
    'discord.com', 'youtube.com', 'google.com', 'github.com', 'wikipedia.org',
    'twitch.tv', 'twitter.com', 'facebook.com', 'instagram.com', 'reddit.com',
    'amazon.com', 'yahoo.com', 'linkedin.com', 'microsoft.com', 'apple.com',
    'steamcommunity.com', 'paypal.com', 'bankofamerica.com', 'ebay.com', 'etsy.com',
    'spotify.com', 'netflix.com', 'dropbox.com', 'icloud.com', 'zoom.us'
]

# Expanded Suspicious keywords
suspicious_keywords = [
    'login', 'secure', 'update', 'verify', 'account', 'signin', 'password', 'payment',
    'gift-card', 'offer', 'credit', 'free', 'bonus', 'survey', 'click', 'win', 'cash',
    'claim', 'help', 'support', 'confirm', 'enter', 'unlock', 'prize', 'check',
    'alert', 'safety', 'verify-account', 'risk-free', 'trial', 'subscription', 'download',
    'install', 'apply', 'confirm-email', 'limited-time', 'act-now', 'fake', 'scam',
    'unsecured', 'non-secure', 'fake-offer', 'unauthorized', 'exclusive', 'restricted',
    'urgent', 'critical', 'banking', 'refundable', 'error', 'immediately', 'action-required',
    'update-now', 'account-alert', 'recovery', 'password-reset', 'locked-account',
    'account-suspended', 'free-gift', 'tax-refund', 'account-breach', 'secure-login',
    'account-recovery', 'withdrawal', 'deposit', 'you-won', 'reward', 'exclusive-offer',
    'prize-claim', 'giftvoucher', 'contest', 'login-page', 'withdraw', 'form-submission',
    'alert-claim', 'money-back', 'data-breach', 'phishing', 'cash-out', 'fake-site',
    'cloning', 'money-laundering', 'you-are-winner', 'account-deactivation', 'refund-request',
    'notification', 'social-engineering', 'security-breach', 'alert-link', 'authorized-access',
    'user-id', 'fake-login', 'password-theft', 'get-rich', 'hoax', 'card-details', 'download-link',
    'net-income', 'unlimited-access', 'online-casino', 'fake-check', 'special-offer',
    'money-transfer', 'limited-offer', 'investment-scheme', 'free-trial', 'blockchain-scam',
    'fake-news', 'survey-link', 'malware-link', 'fraud', 'hacked', 'stolen-info',
    'unauthorized-transaction', 'fake-website', 'unauthorized-action', 'verify-info',
    'pay-now', 'redemption', 'contest-winning', 'earn-money', 'exploits', 'money-making-scheme',
    'fake-prize', 'donate-now', 'scam-site', 'hoax-claim', 'cashback', 'invalid-account',
    'warning', 'blocked', 'secure-your-account', 'immediate-response', 'urgent-message',
    'fraudulent', 'reclaim-money', 'fake-identity', 'check-status'
]

# File where risky links are stored
RISKY_LINKS_FILE = 'risky_links.json'

# Load existing risky links from the JSON file
def load_risky_links():
    try:
        with open(RISKY_LINKS_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []  # Return an empty list if no file exists or if it's empty

# Save risky links to the JSON file
def save_risky_links(risky_links):
    with open(RISKY_LINKS_FILE, 'w') as f:
        json.dump(risky_links, f, indent=4)

# Entropy calculation for randomness detection
def calculate_entropy(text):
    if not text:
        return 0
    length = len(text)
    prob = [float(text.count(c)) / length for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)

# Improved phishing detection algorithm
def calculate_risk(url):
    risk = 0
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    full_url = (domain + parsed_url.path + parsed_url.query).lower()

    # HTTP check (insecure)
    if parsed_url.scheme == 'http':
        risk += 40

    # Unknown domain
    if domain not in whitelisted_domains:
        risk += 20

    # Suspicious keywords in full URL
    for keyword in suspicious_keywords:
        if keyword in full_url:
            risk += 30

    # Typosquatting detection
    known_domains = ['google', 'youtube', 'facebook', 'twitter', 'discord']
    for known in known_domains:
        if known in domain and domain != f"{known}.com":
            risk += 30

    # URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
    if any(shortener in domain for shortener in shorteners):
        risk += 40

    # Entropy check for randomness in domain
    entropy = calculate_entropy(domain.split('.')[0])
    if entropy > 3.5:  # Threshold for "randomness"
        risk += 25

    return min(risk, 100)

# Check if the URL is in the whitelist
def is_whitelisted(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain in whitelisted_domains

# Detect cover-up and masked links
def extract_masked_urls(message):
    markdown_pattern = r'\[([^\]]+)\]\((https?://[^\s]+)\)'  # Detect Markdown [text](url)
    angle_brackets_pattern = r'<(https?://[^\s]+)>'  # Detect <url> format

    urls = []
    markdown_links = re.findall(markdown_pattern, message.content)
    for text, url in markdown_links:
        print(f"Masked Link Detected: {text} -> {url}")
        urls.append(url)
    angle_bracket_links = re.findall(angle_brackets_pattern, message.content)
    urls.extend(angle_bracket_links)
    return urls

# Format the color based on risk
def get_color_for_risk(risk):
    if risk <= 40:
        return 'green'  # Low risk
    elif risk <= 70:
        return 'yellow'  # Medium risk
    else:
        return 'red'  # High risk

# Password generator function
def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# When the bot is ready
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')
    await bot.change_presence(activity=discord.Game(name="!helpme for command list"))

# When a message is received
@bot.event
async def on_message(message):
    extracted_urls = extract_masked_urls(message)
    risky_links = load_risky_links()

    for url in extracted_urls:
        if is_whitelisted(url):
            continue

        risk = calculate_risk(url)
        color = get_color_for_risk(risk)

        print(f"URL: {url} | Risk: {risk}% | Risk Level: {color} (from {message.author} in {message.guild})")

        if url.lower().startswith('http://'):
            print(f"Insecure HTTP URL detected: {url} (from {message.author} in {message.guild})")
            continue

        if risk > 35:
            print(f"Phishing link detected: {url} | Risk: {risk}% | Risk Level: {color} (from {message.author} in {message.guild})")
            risky_links.append({
                'url': url,
                'risk_percentage': risk,
                'risk_level': color
            })
            save_risky_links(risky_links)
            break

    await bot.process_commands(message)

# !password command
@bot.command(name='password')
async def password(ctx):
    password = generate_password(16)
    try:
        await ctx.author.send(f"Here is your secure password: `{password}`")
        await ctx.send("I've sent your secure password in a direct message!")
    except discord.errors.Forbidden:
        await ctx.send(f"{ctx.author.mention}, I was unable to send you a direct message. Please enable your DMs to receive the password.")

# !support command
@bot.command(name='support')
async def support(ctx):
    embed = discord.Embed(
        title="Need Support?",
        description="If you need help or have any questions, join our support server:",
        color=discord.Color.blue()
    )
    embed.add_field(name="Support Server", value="[Click here to join our Discord server!](https://discord.gg/urd5mxBXcW)", inline=False)
    await ctx.send(embed=embed)

# !tokenlogged command
@bot.command(name='tokenlogged')
async def tokenlogged(ctx):
    embed = discord.Embed(
        title="I have been token logged! What should I do?",
        description="Here's what to do next:",
        color=discord.Color.green()
    )
    embed.add_field(name="1. **Change your password immediately**:", value="- Go to [Discord's Password Reset](https://discord.com/password_reset) and reset your password.", inline=False)
    embed.add_field(name="2. **Revoke your token**:", value="- If you're using a self-bot or a custom application, go to [Discord Developer Portal](https://discord.com/developers/applications), find your bot or application, and regenerate the token.", inline=False)
    embed.add_field(name="3. **Revoke any active sessions**:", value="- Go to User Settings -> Devices -> Revoke Sessions to log out from all other devices.", inline=False)
    embed.add_field(name="4. **Review your account for suspicious activity**:", value="- Check your account for any messages or actions you didn't initiate.", inline=False)
    embed.add_field(name="5. **Notify your server admins** (if you're a server bot user):", value="- Inform the admins of any potential issues caused by your token being compromised.", inline=False)
    embed.add_field(name="6. **Contact Discord Support**:", value="- If you're unable to secure your account, contact [Discord Support](https://dis.gd/contact) for further assistance.", inline=False)
    embed.add_field(name="7. **Send any links to admins @ Phishing Authority**:", value="- If you clicked on any suspicious links, send them to the server admins for review. You can contact Phishing Authority using the !support command", inline=False)
    embed.add_field(name="**Stay safe!**", value="- Be cautious of any suspicious messages or activity on your account.", inline=False)
    await ctx.send(embed=embed)

# !isscam command
@bot.command(name='isscam')
async def isscam(ctx, url: str):
    risk = calculate_risk(url)
    if risk > 30:
        embed = discord.Embed(
            title="Risk Detected",
            description=f"**Warning!** The link `{url}` is potentially a scam or phishing attempt. Risk level: **{risk}%**.",
            color=discord.Color.red()
            )
        await ctx.send(embed=embed)
    else:
        embed = discord.Embed(
            title="Potentially safe link",
            description=f"The link `{url}` appears to be safe. Risk level: **{risk}%**. Contact an admin immediately if you're unsure.",
            color=discord.Color.green()
            )
        await ctx.send(embed=embed)

# !helpme command
@bot.command(name='helpme')
async def help(ctx):
    embed = discord.Embed(
        title="Bot Commands",
        description="Here is a list of commands you can use:",
        color=discord.Color.green()
    )
    embed.add_field(name="!helpme", value="Shows this help message.", inline=False)
    embed.add_field(name="!password", value="Generates a secure password and sends it via DM.", inline=False)
    embed.add_field(name="!tokenlogged", value="Provides instructions on what to do if your token is logged.", inline=False)
    embed.add_field(name="!isscam [URL]", value="Checks if the provided URL is a scam or phishing link.", inline=False)
    embed.add_field(name="!support", value="Sends the link to the support server.", inline=False)
    await ctx.send(embed=embed)

# Run the bot
bot.run("YOUR_TOKEN_HERE")
