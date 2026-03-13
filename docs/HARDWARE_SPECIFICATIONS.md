# THE KEN - HARDWARE SPECIFICATIONS

Complete hardware guide covering touchscreen options, pricing, component selection, and technical specifications.

---

## TOUCHSCREEN OPTIONS (CRITICAL DECISION)

### 10.1" IPS RESISTIVE TOUCHSCREEN (BASE MODEL)

- **Supplier:** Waveshare via The Pi Hut
- **Model:** 10.1" IPS Resistive Touch Screen LCD
- **Resolution:** 1024x600 pixels
- **Aspect ratio:** Approximately 16:9 (landscape) - used in portrait (600x1024)
- **Cost:** £67.20
- **Status:** ORDERED (arriving ~3 days)
- **URL:** https://thepihut.com/products/10-1-ips-resistive-touch-screen-lcd-1024x600

**Technology: Resistive**
- Requires physical pressure to register touch
- Works with any stylus, finger, glove, or pointing device
- More forgiving for shaky hands (pressure-activated)
- Less sensitive than capacitive (deliberate touch needed)
- Immune to accidental brushing/water droplets
- Lower cost than capacitive equivalent
- Slightly reduced clarity vs capacitive (due to resistive layer)

**Advantages for elderly users:**
- Pressure-based = less accidental activation
- Works with gloves (winter use)
- Works with any pointing device (pen, stylus, knuckle)
- Forgiving of imprecise touches
- No "ghost touches" from arm resting on screen

**Disadvantages:**
- Requires deliberate pressure (may be harder for very frail users)
- Slightly reduced brightness/clarity vs capacitive
- No multi-touch gestures (not needed for The Ken)
- Feels less "premium" than capacitive

**Recommended for:** Base model, maximizing accessibility and forgiveness

### 13.3" CAPACITIVE TOUCHSCREEN (UPGRADE OPTION)

- **Supplier:** TBD (research needed)
- **Resolution:** 1920x1080 (Full HD) typical
- **Aspect ratio:** 16:9 landscape - used in portrait (1080x1920)
- **Estimated cost:** £95-120
- **Pricing to customer:** Base £275 + £30 upgrade = £305 RRP
- **Status:** NOT YET SOURCED

**Technology: Capacitive**
- Touch detected by electrical properties of skin
- Very sensitive (light touch activation)
- Supports multi-touch (not used in The Ken)
- Clearer, brighter display than resistive
- More "premium" feel

**Advantages:**
- Better visual clarity
- Lighter touch needed
- Larger screen = bigger touch targets
- Better for users with limited hand strength

**Disadvantages:**
- More sensitive = easier accidental touches
- Won't work with gloves
- Won't work with standard stylus (needs capacitive stylus)
- Higher cost
- May register "ghost touches" from arm contact

**Recommended for:** Users with very limited hand strength, or where screen clarity is priority

### 15.6" CAPACITIVE TOUCHSCREEN (PREMIUM OPTION)

- **Supplier:** TBD (research needed)
- **Resolution:** 1920x1080 (Full HD) typical
- **Aspect ratio:** 16:9 landscape - used in portrait (1080x1920)
- **Estimated cost:** £115-140
- **Pricing to customer:** Base £275 + £50 upgrade = £325 RRP
- **Status:** NOT YET SOURCED

**Technology:** Capacitive (same as 13.3")

**Advantages:**
- Largest touch targets (easier to hit)
- Most comfortable viewing distance
- Best for users with vision impairment
- Premium feel

**Disadvantages:**
- Heaviest option (~2kg total device weight)
- Most expensive
- Larger footprint (more table space needed)
- Same capacitive sensitivity issues as 13.3"

**Recommended for:** Care home common areas, users with significant vision impairment

### TOUCHSCREEN COMPARISON TABLE

| Spec | 10.1" Resistive | 13.3" Capacitive | 15.6" Capacitive |
|------|-----------------|-------------------|-------------------|
| Cost (BOM) | £67 | £95-120 (est.) | £115-140 (est.) |
| RRP | £275 | £305 (+£30) | £325 (+£50) |
| Resolution | 1024x600 | 1920x1080 | 1920x1080 |
| Touch type | Pressure | Electrical | Electrical |
| Works with gloves | Yes | No | No |
| Accidental touch | Resistant | Sensitive | Sensitive |
| Clarity | Good | Excellent | Excellent |
| Weight | ~1.5kg | ~1.75kg | ~2.0kg |
| Recommended for | General use | Limited strength | Vision impairment |

---

## CURRENT BOM (10.1" BASE MODEL)

Complete bill of materials for production-ready device:

| Component | Supplier | Cost | Notes |
|-----------|----------|------|-------|
| Raspberry Pi 4 (4GB) | The Pi Hut | £85.00 | Minimum viable for WebRTC + voice |
| 10.1" Resistive Touchscreen | The Pi Hut / Waveshare | £67.00 | ORDERED, arriving ~3 days |
| 16GB SD Card | Amazon | £3.50 | Class 10, A1 rated minimum |
| 720p Camera Module | Amazon | £6.59 | Standard Pi camera |
| USB Microphone | Amazon | £5.29 | Omnidirectional, 3.5mm jack |
| Stereo Speakers (pair) | Amazon | £10.00 | 3W per channel minimum |
| KY-018 Light Sensor | Amazon | £1.50 | For auto-brightness |
| Bluetooth Remote | Amazon | £6.08 | Backup input method |
| Housing (charcoal ABS) | TBD | £12.00 | Injection molded or 3D printed |
| USB-C Power Supply (5V 3A) | Amazon | £7.60 | Official Pi adapter |
| Assembly & Testing | Contract manufacturer | £15.00 | Per-unit labor cost |
| **TOTAL BOM** | | **£219.56** | |
| **RRP** | | **£275.00** | |
| **GROSS MARGIN** | | **£55.44 (20.2%)** | Below 25% target |

---

## RECOMMENDED PRICING ADJUSTMENT

Current margin (20.2%) is below target (25%).

**Option 1: Increase RRP to £299**
- BOM: £219.56
- RRP: £299
- Margin: £79.44 (26.6%) - Meets target
- Justification: Still £100+ cheaper than competitors (GrandPad, Komp)

**Option 2: Reduce component costs**
- Target BOM: £205 (for 25% margin at £275 RRP)
- Savings needed: £14.56
- Possible cuts: Cheaper speakers (£10 → £6), cheaper housing (£12 → £8), smaller SD card (16GB → 8GB saves £1.50)
- Risk: Quality compromise

**Recommendation:** Option 1 (£299 RRP) - maintains quality, competitive pricing, healthy margin.

---

## COMPONENT SELECTION RATIONALE

### Raspberry Pi 4 (4GB) - £85

**Why this model:**
- Minimum RAM for simultaneous WebRTC + voice recognition
- Proven hardware support for Raspberry Pi OS
- Large community, extensive documentation
- GPIO for sensors, cameras, buttons

**Alternatives considered:**
- Raspberry Pi 4 (2GB): £55 - Too limited for WebRTC + voice processing
- Orange Pi 5: £60 - Cheaper but inconsistent software support
- Le Potato: £35 - Not powerful enough for video calling
- Raspberry Pi Zero 2 W: £15 - Insufficient for video calls

**Decision:** 4GB is minimum viable. 8GB unnecessary (£20 more, no benefit).

### Waveshare 10.1" Resistive Touchscreen - £67

**Why resistive over capacitive:**
- More forgiving for shaky hands (pressure-based)
- Works with gloves (winter use, medical gloves in care homes)
- Immune to accidental touches (arm resting on screen)
- Lower cost
- Better for elderly users who may press hard

**Why 10.1" size:**
- Optimal balance of visibility and portability
- 4 contact tiles fit comfortably (2x2 grid)
- Text readable at 22px+ font sizes
- Not too heavy (~1.5kg total device weight)
- Fits on bedside tables, small desks

**Alternatives considered:**
- 7" touchscreen: £40 - Too small, text unreadable
- 13.3" capacitive: £100 - Better clarity but more sensitive, higher cost
- 15.6" capacitive: £130 - Best visibility but heavy, expensive, oversized

**Decision:** 10.1" resistive for base model. Offer 13.3"/15.6" capacitive as upgrades for specific needs (vision impairment, care homes).

### 16GB SD Card - £3.50

**Why 16GB:**
- Raspberry Pi OS + Electron + dependencies: ~4GB
- Video voicemail cache (3 months): ~2GB
- Photos, contacts, logs: ~1GB
- Total usage: ~7GB
- 16GB provides 2x headroom

**Alternatives considered:**
- 8GB: £2.00 - Too tight, no room for growth
- 32GB: £5.00 - Unnecessary, doubles cost for no benefit
- 64GB: £8.00 - Complete overkill

**Decision:** 16GB Class 10, A1 rated (application performance).

### 720p Camera Module - £6.59

**Why 720p:**
- Sufficient for video calling (Daily.co supports 720p well)
- Lower bandwidth than 1080p (better for rural broadband)
- Cheaper than 1080p alternatives
- Standard Pi camera module (proven compatibility)

**Upgrade option:** Wide-angle 1080p (120° FOV) - £12
- Shows more of room (group calls, family gatherings)
- Better for users who move around while talking
- Higher resolution for clearer video
- Pricing: Base + £4 upgrade = £279 RRP

**Alternatives considered:**
- 480p webcam: £4 - Too low quality, grainy video
- 1080p standard FOV: £10 - Marginal improvement, higher cost
- 4K camera: £50 - Overkill, bandwidth-heavy, expensive

**Decision:** 720p base, offer 1080p wide-angle as upgrade.

### USB Microphone - £5.29

**Why USB over 3.5mm jack:**
- Better noise cancellation
- Clearer audio for voice commands
- Digital signal (no analog interference)
- Standard USB-A (no adapters needed)

**Specifications:**
- Omnidirectional pickup
- 50Hz-16kHz frequency response
- USB 2.0 interface
- Plug-and-play (no drivers)

**Alternatives considered:**
- 3.5mm microphone: £3 - More interference, lower quality
- USB array microphone: £15 - Better but 3x cost, diminishing returns
- Bluetooth headset: £20 - Adds pairing complexity

**Decision:** Simple USB microphone for reliability and clarity.

### Stereo Speakers - £10

**Why stereo over mono:**
- Better audio quality for voices
- Room-filling sound (elderly often have hearing loss)
- Cheap upgrade from mono (£2 difference)

**Specifications:**
- 3W per channel minimum
- 3.5mm jack input
- Powered via USB or batteries

**Upgrade option:** Premium speakers (5W, better bass) - £25
- Clearer voice reproduction
- Higher volume for hearing impairment
- Pricing: Base + £15 upgrade (not offered in base configurator)

**Alternatives considered:**
- Mono speaker: £8 - Acceptable but less immersive
- Bluetooth speaker: £15 - Pairing complexity, battery management
- Built-in Pi audio: £0 - Very poor quality

**Decision:** £10 stereo speakers for base. Consider premium upgrade later.

### KY-018 Light Sensor - £1.50

**Why KY-018:**
- Analog photoresistor (simple, cheap)
- No I2C configuration needed
- Direct GPIO connection
- Sufficient accuracy for auto-brightness

**Purpose:**
- Auto-adjust screen brightness based on ambient light
- Nightlight mode (dim after 9pm, brighten at 7am)
- Save power in dark rooms

**Alternatives considered:**
- BH1750 digital sensor: £3 - More accurate but unnecessary precision
- TSL2561 lux sensor: £5 - Overkill for this use case
- No sensor (manual brightness): £0 - User has to adjust manually

**Decision:** KY-018 for cost-effectiveness and simplicity.

### Bluetooth Remote - £6.08

**Why include:**
- Backup input if touchscreen fails
- Volume control without touching screen
- Navigate UI if screen unresponsive
- Familiar form factor for elderly (like TV remote)

**Specifications:**
- Standard Bluetooth HID
- Volume up/down, play/pause, arrow keys
- AAA batteries (6-month life)
- Auto-pairs with Pi

**Alternatives considered:**
- No remote: £0 - No backup if touchscreen fails
- IR remote: £4 - Requires line-of-sight, less reliable
- Custom remote: £15 - Expensive, long lead time

**Decision:** Include basic Bluetooth remote for reliability.

### Housing - £12

**Why charcoal ABS plastic:**
- Warm, approachable color (not stark white or black)
- Durable, impact-resistant
- Easy to clean (care home use)
- Hides fingerprints better than white

**Manufacturing:**
- Injection molding for volume (1000+ units)
- 3D printing for prototypes/small batches (<100 units)
- Positive-lock stand mechanism (portrait orientation)
- Vent holes for Pi heat dissipation
- Cable management clips

**Alternatives considered:**
- White plastic: £12 - Shows dirt, feels clinical
- Black plastic: £12 - Too dark, intimidating
- Wood effect: £20 - Expensive, harder to clean
- Metal: £30 - Heavy, expensive, cold to touch

**Decision:** Charcoal ABS for warmth and practicality.

### USB-C Power Supply (5V 3A) - £7.60

**Why official Pi adapter:**
- Certified for Pi 4 power requirements
- Reliable, no voltage sag
- Built-in overcurrent protection
- UK plug included

**Specifications:**
- 5V DC, 3A output (15W)
- USB-C connector
- 1.5m cable length
- CE certified

**Alternatives considered:**
- Generic USB-C charger: £4 - Unreliable, may not provide 3A
- USB-C PD charger: £15 - Overkill, more expensive
- Powered via USB hub: £0 - Not enough power for Pi + screen

**Decision:** Official adapter for reliability and safety.

---

## ASSEMBLY & QUALITY CONTROL

### Assembly Process (contract manufacturer)

1. Flash SD card with pre-configured Raspberry Pi OS
2. Install Pi in housing (secure with screws)
3. Connect touchscreen ribbon cable
4. Connect camera, microphone, speakers
5. Install light sensor on GPIO pins
6. Pair Bluetooth remote
7. Close housing, apply branding sticker
8. Quality test (boot, touchscreen, camera, audio)
9. Package with power supply, quick start guide

- **Time per unit:** 15-20 minutes
- **Labor cost:** £15 per unit (assuming £45/hour labor rate)

### Quality Checks

- Powers on successfully
- Touchscreen calibrated and responsive
- Camera image clear
- Microphone picks up voice
- Speakers produce clear audio
- Light sensor adjusts brightness
- Remote pairs and controls volume
- Ethernet + WiFi connect

**Failure rate target:** <2% (industry standard for electronics assembly)

---

## UPGRADE PATHS & ACCESSORIES

### Display Upgrades (from configurator)

**13.3" Capacitive Touch:**
- BOM cost: £95-120 (TBD)
- Customer price: +£30 (£305 total RRP)
- Use case: Better for limited hand strength

**15.6" Capacitive Touch:**
- BOM cost: £115-140 (TBD)
- Customer price: +£50 (£325 total RRP)
- Use case: Vision impairment, care homes

### Camera Upgrades

**Wide-angle 1080p (120° FOV):**
- BOM cost: +£6 (£12 total vs £6 baseline)
- Customer price: +£4 (£279 total RRP)
- Use case: Group calls, active users

### Battery Backup

**2-hour battery (2000mAh):**
- BOM cost: +£6
- Customer price: +£6 (£281 total RRP)
- Use case: Power outages, portability

**4-hour battery (4000mAh):**
- BOM cost: +£10
- Customer price: +£10 (£285 total RRP)
- Use case: Extended portability, frequent outages

### Accessories (Sold Separately)

| Accessory | Cost | RRP | Notes |
|-----------|------|-----|-------|
| Protective Case | £18 | £30 | Waterproof, carry handles, transparent front |
| Emergency Pendant | £12 | £20 | Wearable, BLE, SOS button |
| Wireless Headphones | £15 | £25 | Over-ear, wireless, 20-hour battery |
| Keyboard & Mouse | £8 | £15 | Large keys, high contrast, USB dongle |
| Wall Mount | £5 | £15 | Adjustable angle, VESA-compatible |
| Remote Control (extra) | £6 | £15 | Replacement/spare for included remote |

---

## MANUFACTURING CONSIDERATIONS

### Minimum Order Quantities (MOQ)

**Touchscreens:**
- 10.1" resistive: 50 units MOQ
- 13.3" capacitive: 100 units MOQ (estimated)
- 15.6" capacitive: 100 units MOQ (estimated)

**Housing (injection molding):**
- MOQ: 500 units
- Tooling cost: £3,000-5,000 one-time
- Per-unit cost drops to £8-10 at volume

**Recommendation:** Start with 3D-printed housing (<100 units), transition to injection molding at 500+ units.

### Lead Times

| Component | Lead Time |
|-----------|-----------|
| Raspberry Pi 4 | 1-2 weeks (stock permitting) |
| Touchscreens | 2-4 weeks (Waveshare stock) |
| Custom housing | 6-8 weeks (tooling + production) |
| SD cards, cameras, accessories | 1 week (Amazon/AliExpress) |

**Total lead time (first production run):** 8-10 weeks

### Supplier Relationships

**The Pi Hut (UK):**
- Pi 4 boards
- Touchscreens (Waveshare distributor)
- Cameras, sensors
- UK-based, fast shipping

**Hannah (factory contacts):**
- Contract manufacturing
- Housing production (injection molding)
- Assembly & QC

**AliExpress/Alibaba:**
- Speakers, microphones (bulk orders)
- Lower cost, longer lead times
- Quality variance (need samples first)

---

## COST OPTIMIZATION OPPORTUNITIES

**Current BOM:** £219.56
**Target for 25% margin at £275 RRP:** £206.25
**Savings needed:** £13.31

### Option 1: Component Downgrades

- Speakers: £10 → £6 (saves £4)
- Housing: £12 → £8 (saves £4, use thinner plastic)
- SD card: 16GB → 8GB (saves £1.50)
- Bluetooth remote: Remove from base (saves £6.08)
- **Total savings: £15.58** - Exceeds target

**Risk:** Lower quality, fewer features, customer dissatisfaction

### Option 2: Volume Discounts

- Raspberry Pi 4: £85 → £75 (10+ unit discount)
- Touchscreen: £67 → £60 (50+ unit MOQ)
- Housing: £12 → £8 (injection molding at 500+ units)
- **Total savings: £19** - Exceeds target

**Risk:** Requires capital for bulk purchase, inventory risk

### Option 3: Increase RRP

- RRP: £275 → £299
- BOM: £219.56 (unchanged)
- Margin: £79.44 (26.6%) - Meets target
- Still competitive vs GrandPad (£80/month = £960/year), Komp (£30/month = £360/year)

**Risk:** Minimal - still significantly cheaper than competitors

**Recommendation:** Option 3 (increase RRP to £299). Maintains quality, healthy margin, competitive positioning.

---

## HARDWARE ROADMAP

### Phase 1: Prototype (Current)

- 10.1" resistive touchscreen (ordered)
- Raspberry Pi 4 (4GB)
- 3D-printed housing prototype
- Test all sensors, cameras, audio
- Validate touch accuracy with elderly users

### Phase 2: Beta Units (50 units)

- Same spec as prototype
- 3D-printed housing (batch production)
- Test with Phil's parents, Pierce's care home contacts
- Gather feedback on touch sensitivity, screen size

### Phase 3: Production (500+ units)

- Transition to injection-molded housing
- Negotiate volume discounts on Pi boards
- Lock in touchscreen supplier (50+ unit MOQ)
- Offer 13.3"/15.6" capacitive options

### Phase 4: Scale (1000+ units)

- Multiple housing color options (charcoal, cream, white)
- Pre-configured SD cards (bulk flashing)
- Retail partnerships (care home suppliers, mobility shops)

---

**END OF HARDWARE SPECIFICATIONS**

This document covers all hardware decisions, component selection rationale, pricing strategies, and manufacturing considerations. Use this for:
- BOM planning
- Supplier negotiations
- Cost optimization
- Quality control
- Production scaling
