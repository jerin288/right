# Railway Deployment Guide

## Quick Start

### 1. Prerequisites
- Git installed
- Railway account (sign up at railway.app)
- GitHub account (recommended)

### 2. Deploy to Railway

#### Option A: Deploy via GitHub (Recommended)

1. **Push to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit for Railway deployment"
   git branch -M main
   git remote add origin https://github.com/yourusername/right_fit.git
   git push -u origin main
   ```

2. **Connect to Railway**:
   - Go to https://railway.app
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your `right_fit` repository
   - Railway will automatically detect and deploy your Flask app

3. **Add PostgreSQL Database**:
   - In your Railway project dashboard
   - Click "New" → "Database" → "Add PostgreSQL"
   - Railway automatically creates `DATABASE_URL` variable

4. **Add Environment Variables**:
   - Go to your service → "Variables"
   - Add the following variables:

   ```
   SECRET_KEY=<use-the-generated-key-from-terminal>
   SESSION_COOKIE_SECURE=True
   CASHFREE_APP_ID=<your-cashfree-app-id>
   CASHFREE_SECRET_KEY=<your-cashfree-secret>
   CASHFREE_ENVIRONMENT=PRODUCTION
   BASE_URL=<your-railway-app-url>
   ```

5. **Get Your App URL**:
   - Go to "Settings" → "Domains"
   - Railway provides a free domain like: `yourapp.up.railway.app`
   - Copy this URL and set it as `BASE_URL` environment variable

#### Option B: Deploy via Railway CLI

1. **Install Railway CLI**:
   ```bash
   npm install -g @railway/cli
   ```

2. **Login to Railway**:
   ```bash
   railway login
   ```

3. **Initialize Project**:
   ```bash
   railway init
   ```

4. **Deploy**:
   ```bash
   railway up
   ```

5. **Add PostgreSQL**:
   ```bash
   railway add postgresql
   ```

6. **Set Environment Variables**:
   ```bash
   railway variables set SECRET_KEY=<your-secret-key>
   railway variables set SESSION_COOKIE_SECURE=True
   railway variables set CASHFREE_APP_ID=<your-app-id>
   railway variables set CASHFREE_SECRET_KEY=<your-secret>
   railway variables set CASHFREE_ENVIRONMENT=PRODUCTION
   ```

### 3. Environment Variables Reference

Copy these to Railway Dashboard → Your Service → Variables:

#### Required Variables
```
SECRET_KEY=abea6687c180dc7d9e7e343f871748293a50bbad07431fe96153742fcb05f440
DATABASE_URL=<automatically-set-by-railway>
SESSION_COOKIE_SECURE=True
CASHFREE_APP_ID=<your-cashfree-app-id>
CASHFREE_SECRET_KEY=<your-cashfree-secret-key>
CASHFREE_ENVIRONMENT=PRODUCTION
BASE_URL=https://your-app.up.railway.app
```

#### Optional Variables (for SMS notifications)
```
ADMIN_PHONE_NUMBER=7510556919
SMS_GATEWAY_API_KEY=<your-fast2sms-api-key>
USE_SMS_NOTIFICATION=False
```

### 4. Post-Deployment

1. **Check Deployment Logs**:
   - In Railway dashboard, go to "Deployments"
   - View logs to ensure successful deployment

2. **Initialize Database**:
   - Railway will automatically run `build.sh` which creates admin user
   - Default admin credentials:
     - Username: `admin`
     - Password: `admin123`

3. **Test Your Application**:
   - Visit your Railway domain
   - Test user registration, login, and checkout
   - **Important**: Change admin password immediately!

4. **Set Up Payment Gateway**:
   - Configure Cashfree webhook URL: `https://your-app.up.railway.app/payment/webhook`
   - Update return URL: `https://your-app.up.railway.app/payment/callback`

### 5. Troubleshooting

**Database Connection Issues**:
- Verify `DATABASE_URL` is set by Railway
- Check if PostgreSQL service is running

**Build Failures**:
- Check Railway build logs
- Ensure all dependencies in `requirements.txt` are correct
- Verify Python version matches `runtime.txt`

**Application Errors**:
- Check Railway deployment logs
- Verify all environment variables are set correctly
- Ensure `SECRET_KEY` and `CASHFREE_*` variables are configured

**Static Files Not Loading**:
- Railway serves static files automatically with Flask
- Ensure `static/` folder is committed to Git

### 6. Updating Your App

```bash
git add .
git commit -m "Your update message"
git push origin main
```

Railway will automatically redeploy when you push to GitHub!

### 7. Cost & Limits

- **Free Tier**: $5 credit/month (enough for hobby projects)
- **PostgreSQL**: Included in free tier
- **Custom Domain**: Free with Pro plan ($20/month)
- **Bandwidth**: 100 GB/month on free tier

### 8. Security Checklist

✅ Generated strong `SECRET_KEY`
✅ Set `SESSION_COOKIE_SECURE=True`
✅ Changed default admin password
✅ Using PostgreSQL (not SQLite) in production
✅ Set `CASHFREE_ENVIRONMENT=PRODUCTION` for live payments
✅ Added `.env` to `.gitignore`
✅ Never committed sensitive credentials to Git

### 9. Monitoring

- **Metrics**: Railway dashboard shows CPU, memory, and network usage
- **Logs**: Real-time logs available in dashboard
- **Alerts**: Set up notifications in Railway settings

---

## Support

- Railway Docs: https://docs.railway.app
- Flask Docs: https://flask.palletsprojects.com
- Cashfree Docs: https://docs.cashfree.com

## Quick Commands Reference

```bash
# View logs
railway logs

# Open your app
railway open

# List services
railway status

# Connect to PostgreSQL
railway connect postgres

# Run database migrations
railway run python -c "from app import db; db.create_all()"
```
