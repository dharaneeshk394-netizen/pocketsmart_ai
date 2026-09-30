# PocketSmart AI — Smart Budget & Recommendation Assistant

**PocketSmart AI** is a smart budget planning and recommendation platform designed for college project requirements and modern web environments. It provides budget-aware curation and product matching across three core real-world planning modules: **Home Interior**, **Party & Events**, and **Jewelry Matching**.

The system pairs **Google Gemini AI** (`@google/genai`) with deterministic backend price verification, ensuring that AI arithmetic is never blindly trusted, and delivers an intuitive user experience with provider attribution (Amazon, Flipkart, IKEA, Swiggy, Zomato, OYO, and Tanishq).

---

## 🌟 Core Modules

### 1. Home Interior Budget Planner
* **Input Parameters**:
  - Total project budget limit & currency
  - Room type (Living Room, Master Bedroom, Kids Bedroom, Kitchen, Home Office, Balcony)
  - Room size (Compact 10x12 ft, Medium 14x16 ft, Spacious 20x24 ft)
  - Interior style (Modern Minimalist, Scandinavian, Bohemian, Industrial, Traditional Indian, Japandi)
  - Color preference & palette (Warm Neutrals, Earthy & Botanical, Jewel Tones, Cool Greys)
  - Specific furniture items: Sofa, Dining Table, Bed, Storage Units
  - Fixtures & Ambiance: Lighting requirements, Ceiling fans, Area rugs, Curtains, Wall art, Planters
  - Quantities and custom constraints (e.g. pet-friendly fabrics, low maintenance)
* **Recommendations Output**:
  - Itemized product recommendations with verified market prices
  - Category, quantity, line-item totals, and provider assignment (IKEA, Urban Ladder, Pepperfry, Amazon, Flipkart)
  - Design rationale and color scheme harmony notes
  - Deterministic backend math recalculation ensuring plans never exceed budget cap
  - Direct catalog search links and bookmarking

### 2. Party Budget Planner
* **Input Parameters**:
  - Total budget & guest count
  - Event type (Birthday, Wedding, Corporate, Anniversary, Family gathering, Other)
  - Date & venue/location
  - Setting type: Indoor with AC, Outdoor Garden, Hybrid Terrace, Residential
  - Food & catering preferences (Buffet, finger foods, mocktails, custom cake)
  - Decoration style & themes (Balloon arch, floral centerpieces, fairy lights, neon signs)
  - Entertainment requirements (Sound system, curated playlist, live band, emcee, party games)
  - Accommodation needs (OYO / hotel room requirements for out-of-town guests)
* **Budget Allocation Engine**:
  - Mathematically balances the budget across 6 key hospitality pillars:
    - **Food & Catering**
    - **Venue Hall**
    - **Decoration**
    - **Entertainment**
    - **Accommodation**
    - **Miscellaneous Reserve**
  - Calculates exact **Cost per Guest** metrics
  - Maps packages to providers: Swiggy, Zomato, OYO, Amazon, BookMyShow

### 3. Jewelry Budget Planner & Multimodal Stylist
* **Input Parameters**:
  - Total budget cap
  - Occasion (Festive Wedding Guest, Bridal, Cocktail Evening, Traditional Festival, Daily Office)
  - Jewelry type (Necklace Set, Statement Earrings, Bangles/Bracelet, Cocktail Ring, Choker & Maang Tikka)
  - Craftsmanship & style (Royal Kundan & Polki, Temple Antique, Contemporary Fine Jewelry, Meenakari)
  - Metal preference (Yellow Gold 22K/18K, Rose Gold, Platinum, 925 Sterling Silver)
  - Color & gemstone accents (Emerald, Ruby, Sapphire, Pearl, Clear Diamond)
  - Outfit description & neckline context
  - **Optional Outfit Image Upload**: Visual styling analysis using Gemini vision with magic-byte and MIME validation
* **Privacy-First Visual Analysis**:
  - Evaluates jewelry-relevant visual characteristics only:
    - Dominant fabric colors & tones
    - Formality & style aesthetic
    - Recommended metal finishes and gemstone hues
    - Neckline styling advice
  - **Strict Privacy Safeguard**: Never infers personal identities, demographics, or sensitive attributes.
  - Matches items to brands: Tanishq, CaratLane, Kalyan Jewellers, Amazon, Myntra

---

## 🛡️ Provider Architecture & Safe Demo Mode

In accordance with the project specification:
* **Supported Providers**: Amazon, Flipkart, IKEA, Swiggy, Zomato, OYO, Myntra, Tanishq, CaratLane, Pepperfry, Urban Ladder.
* **Safe Demo Provider Mode (`PROVIDER_MODE=demo`)**:
  - The application clearly informs users that product availability and pricing are synthetic approximations for college project demonstration purposes.
  - Generates valid, safe search and catalog exploration links.
  - Modular provider abstraction layer enables swapping mock providers for real partner APIs without altering core planner logic.

---

## 🔒 Authentication & Data Isolation

* Real JWT token and session management with HMAC-SHA256 signatures and 7-day expiration.
* Salted password hashing using SHA-512 / PBKDF2 with 100,000 iterations.
* Complete data isolation: Users only access their own plan history, saved recommendations, and custom inputs (IDOR protected).
* Quick 1-click Demo Sign In (`demo@pocketsmart.ai`) for instant evaluation.

---

## 🗄️ Relational Database Schema (PostgreSQL)

Located in `/database/schema.sql` and `/backend/schema.sql`:
1. `users`: Stores user profile, currency choice, hashed credentials.
2. `plan_requests`: Persists runs across the 3 planners (`home`, `party`, `jewelry`) with raw inputs, budget limits, calculated totals, AI summaries, and breakdowns.
3. `recommendation_items`: Line-item product recommendations with verified prices, provider tags, and status.
4. `saved_recommendations`: Bookmarked items with categories, provider tags, and quick search links.
5. `uploaded_images`: Metadata for optional outfit images and extracted visual traits.

When `DATABASE_URL` is configured, PostgreSQL connection pool (`pg.Pool`) automatically handles relational persistence.

---

## 🏗️ Architecture & How to Run

### Interactive Full-Stack Server
The app runs on port 3000 via a full-stack Node/Express server (`server.ts`) mounting Vite middlewares:
```bash
npm run dev
# Serves frontend & API endpoints on http://localhost:3000
```

### Production Build
```bash
npm run build
npm start
```

### Environment Variables
Configure `.env` based on `.env.example`:
```env
DATABASE_URL=postgresql://user:password@localhost:5432/pocketsmart
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
PORT=3000
CORS_ORIGIN=http://localhost:3000
JWT_SECRET=your_secure_random_signing_key
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=120
RATE_LIMIT_SENSITIVE_MAX=30
```

### API Endpoints
* `POST /api/planners/home`: Generate Home Interior plan
* `POST /api/planners/party`: Generate Party & Event plan with budget breakdown
* `POST /api/planners/jewelry`: Generate Jewelry plan with optional multimodal vision
* `GET /api/history`: List past plans for user
* `GET /api/history/:id`: Get full itemized details of past plan
* `DELETE /api/history/:id`: Delete plan from history
* `GET /api/recommendations/saved`: List bookmarked wishlist items
* `POST /api/recommendations/saved`: Save recommended item
* `DELETE /api/recommendations/saved/:id`: Remove saved item
* `POST /api/auth/login`: User sign in
* `POST /api/auth/register`: User registration
* `GET /api/auth/me`: Current user session
* `POST /api/auth/logout`: User logout
* `GET /api/demo/status`: Demo provider status info
* `POST /api/demo/seed-samples`: Seed demo sample plans
* `GET /api/health`: Health status check
