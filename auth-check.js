// Shared Client-Side Authentication and Session Script for TransformAI
document.addEventListener('DOMContentLoaded', () => {
    // 1. Fetch User Data
    fetch('/api/auth/me')
        .then(response => {
            if (!response.ok) {
                // If not authenticated, redirect to login page
                window.location.href = '/';
                return;
            }
            return response.json();
        })
        .then(data => {
            if (data && data.user) {
                updateUserUI(data.user);
            }
        })
        .catch(err => {
            console.error('Auth verification error:', err);
            window.location.href = '/';
        });

    // 2. Set Up Sign Out Buttons
    setupSignOut();
});

function updateUserUI(user) {
    // Determine initials
    let initials = 'US';
    if (user.name) {
        const parts = user.name.split(' ');
        if (parts.length > 1) {
            initials = (parts[0][0] + parts[1][0]).toUpperCase();
        } else {
            initials = user.name.substring(0, 2).toUpperCase();
        }
    } else if (user.email) {
        initials = user.email.substring(0, 2).toUpperCase();
    }

    // Find and update avatar displays
    const avatars = document.querySelectorAll('.bg-primary-container\\/30.flex.items-center.justify-center.text-primary.font-semibold.text-xs');
    avatars.forEach(avatar => {
        avatar.textContent = initials;
        avatar.title = user.name || user.email;
    });

    // Also update any greeting/username text if it exists (e.g. Welcome back, Name)
    const welcomeHeading = document.querySelector('h2.font-headline-lg');
    if (welcomeHeading && welcomeHeading.textContent.includes('Welcome Back')) {
        welcomeHeading.innerHTML = `Welcome Back, <span class="text-primary-container glow-text">${user.name || 'User'}</span>`;
    }
}

function setupSignOut() {
    // Find logout links
    const signoutLinks = document.querySelectorAll('a[href="index.html"]');
    signoutLinks.forEach(link => {
        // Change href so it doesn't navigate directly
        link.href = '#';
        link.addEventListener('click', async (e) => {
            e.preventDefault();
            try {
                const response = await fetch('/api/auth/logout', { method: 'POST' });
                if (response.ok) {
                    window.location.href = '/';
                } else {
                    alert('Sign out failed');
                }
            } catch (err) {
                console.error('Sign out error:', err);
            }
        });
    });
}
