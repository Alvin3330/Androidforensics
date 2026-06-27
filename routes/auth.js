// Authentication Functions

function toggleRegister() {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    loginForm.style.display = loginForm.style.display === 'none' ? 'block' : 'none';
    registerForm.style.display = registerForm.style.display === 'none' ? 'block' : 'none';
}

async function handleRegister(event) {
    event.preventDefault();

    const investigator_id = document.getElementById('reg_investigator_id').value;
    const name = document.getElementById('reg_name').value;
    const email = document.getElementById('reg_email').value;
    const password = document.getElementById('reg_password').value;

    try {
        await register(investigator_id, name, email, password);

        const successDiv = document.getElementById('regSuccessMessage');
        successDiv.textContent = '✅ Registration successful! Please login.';
        successDiv.classList.add('show');

        // Clear form
        event.target.reset();

        // Show login form after 2 seconds
        setTimeout(() => {
            toggleRegister();
        }, 2000);

    } catch (error) {
        const errorDiv = document.getElementById('regErrorMessage');
        errorDiv.textContent = '❌ ' + error.message;
        errorDiv.classList.add('show');
    }
}

async function handleLogin(event) {
    event.preventDefault();

    const investigator_id = document.getElementById('investigator_id').value;
    const password = document.getElementById('password').value;

    try {
        const result = await login(investigator_id, password);

        // Save token and user info
        setToken(result.token);
        localStorage.setItem('investigatorId', result.investigator_id);
        localStorage.setItem('investigatorName', result.name);

        // Clear error messages
        document.getElementById('errorMessage').classList.remove('show');

        // Redirect to dashboard
        window.location.href = 'dashboard.html';

    } catch (error) {
        const errorDiv = document.getElementById('errorMessage');
        errorDiv.textContent = '❌ Login failed: ' + error.message;
        errorDiv.classList.add('show');
    }
}

// Check if already logged in
window.addEventListener('load', () => {
    if (window.location.pathname.includes('index.html') || window.location.pathname === '/') {
        if (isLoggedIn()) {
            window.location.href = 'dashboard.html';
        }
    }
});