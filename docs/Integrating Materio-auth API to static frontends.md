# Direct API Integration Guide

This guide explains how to integrate the Materio authentication system directly into your frontend application using API calls instead of redirects. This approach allows you to create custom UI components that match your site's design while leveraging the authentication backend.

## API Endpoints

The authentication system provides the following API endpoints:

| Endpoint | Method | Description | Request Body | Response |
|----------|--------|-------------|-------------|----------|
| `/.netlify/functions/signup` | POST | Register a new user | `{ email, username, password, displayName, profilePicture? }` | `{ message, token, user }` |
| `/.netlify/functions/login` | POST | Authenticate a user | `{ username, password }` | `{ token, user }` |
| `/.netlify/functions/forgot-password` | POST | Request password reset | `{ email }` | `{ message }` |
| `/.netlify/functions/forgot-password` | PUT | Reset password using recovery key | `{ email, recoveryKey, newPassword }` | `{ message }` |
| `/.netlify/functions/profile` | GET | Get user profile | - | `{ user }` |
| `/.netlify/functions/profile` | PUT | Update user profile | `{ username?, displayName?, currentPassword?, newPassword?, profilePicture?, generateNewRecoveryKey? }` | `{ message, user, recoveryKey? }` |
| `/.netlify/functions/profile` | DELETE | Delete user account | `{ password }` | `{ message }` |

## Authentication Flow

### 1. Setup Base API Module

First, create a base API module to handle requests:

```javascript
// auth-api.js

const API_URL = 'https://auth-materioa.netlify.app/.netlify/functions';

// Helper function for API requests
async function makeApiRequest(endpoint, method = 'GET', data = null, requiresAuth = false) {
  try {
    // Setup request options
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'same-origin'
    };
    
    // Add authentication token if required
    if (requiresAuth) {
      const token = localStorage.getItem('materio_auth_token');
      if (!token) {
        throw new Error('Authentication required');
      }
      options.headers['Authorization'] = `Bearer ${token}`;
    }
    
    // Add request body for POST, PUT, DELETE methods
    if (data && (method === 'POST' || method === 'PUT' || method === 'DELETE')) {
      options.body = JSON.stringify(data);
    }
    
    // Make fetch request
    const response = await fetch(`${API_URL}/${endpoint}`, options);
    
    // Parse response
    const result = await response.json();
    
    // Handle API errors
    if (!response.ok) {
      throw new Error(result.error || result.message || 'Something went wrong');
    }
    
    return result;
  } catch (error) {
    console.error('API Request Error:', error);
    throw error;
  }
}

// Authentication functions
export async function signUp(userData) {
  return makeApiRequest('signup', 'POST', userData);
}

export async function login({ username, password }) {
  const result = await makeApiRequest('login', 'POST', { username, password });
  
  // Save token and user data
  if (result.token) {
    localStorage.setItem('materio_auth_token', result.token);
    localStorage.setItem('materio_user', JSON.stringify(result.user));
  }
  
  return result;
}

export async function forgotPassword(email) {
  return makeApiRequest('forgot-password', 'POST', { email });
}

export async function resetPassword(resetData) {
  return makeApiRequest('forgot-password', 'PUT', resetData);
}

export async function getUserProfile() {
  return makeApiRequest('profile', 'GET', null, true);
}

export async function updateUserProfile(profileData) {
  const result = await makeApiRequest('profile', 'PUT', profileData, true);
  
  // Update stored user data if successful
  if (result.user) {
    localStorage.setItem('materio_user', JSON.stringify(result.user));
  }
  
  return result;
}

export async function deleteAccount(password) {
  const result = await makeApiRequest('profile', 'DELETE', { password }, true);
  
  // Clear stored data on successful deletion
  if (result.message) {
    localStorage.removeItem('materio_auth_token');
    localStorage.removeItem('materio_user');
  }
  
  return result;
}

export function logout() {
  localStorage.removeItem('materio_auth_token');
  localStorage.removeItem('materio_user');
}

export function isAuthenticated() {
  return localStorage.getItem('materio_auth_token') !== null;
}

export function getCurrentUser() {
  const userData = localStorage.getItem('materio_user');
  return userData ? JSON.parse(userData) : null;
}
```

## UI Implementation Examples

### Login Form

```html
<form id="loginForm" class="custom-form">
  <div class="form-group">
    <label for="email">Email</label>
    <input type="email" id="email" required>
  </div>
  <div class="form-group">
    <label for="password">Password</label>
    <input type="password" id="password" required>
  </div>
  <div class="form-actions">
    <button type="submit" class="btn-primary">Login</button>
  </div>
  <div class="form-links">
    <a href="#" id="forgotPasswordLink">Forgot Password?</a>
    <a href="#" id="signupLink">Create Account</a>
  </div>
</form>

<div id="notification" class="notification"></div>
```

```javascript
import { login } from './auth-api.js';

document.addEventListener('DOMContentLoaded', function() {
  const loginForm = document.getElementById('loginForm');
  const notification = document.getElementById('notification');
  
  loginForm.addEventListener('submit', async function(e) {
    e.preventDefault();
      const usernameOrEmail = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    try {
      // Show loading state
      const submitButton = this.querySelector('button[type="submit"]');
      const originalText = submitButton.textContent;
      submitButton.disabled = true;
      submitButton.textContent = 'LOGGING IN...';
      
      // Call login API
      const response = await login({ username: usernameOrEmail, password });
      
      // Show success message
      showNotification('Login successful!', 'success');
      
      // Redirect or update UI based on authenticated state
      // Example: refreshUserInterface();
      
    } catch (error) {
      showNotification(error.message || 'Login failed', 'error');
    } finally {
      // Reset button state
      submitButton.disabled = false;
      submitButton.textContent = originalText;
    }
  });
  
  function showNotification(message, type = 'info') {
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
      notification.style.display = 'none';
    }, 5000);
  }
});
```

### Sign Up Form

```html
<form id="signupForm" class="custom-form">
  <div class="form-group">
    <label for="email">Email</label>
    <input type="email" id="email" required>
  </div>
  <div class="form-group">
    <label for="username">Username</label>
    <input type="text" id="username" required>
  </div>
  <div class="form-group">
    <label for="displayName">Display Name</label>
    <input type="text" id="displayName" required>
  </div>
  <div class="form-group">
    <label for="password">Password</label>
    <input type="password" id="password" required>
  </div>
  <div class="form-group">
    <label for="confirmPassword">Confirm Password</label>
    <input type="password" id="confirmPassword" required>
  </div>
  <div class="form-group profile-picture-upload">
    <label>Profile Picture (Optional)</label>
    <div class="upload-container">
      <img id="picturePreview" src="path/to/default-avatar.svg" alt="Preview">
      <input type="file" id="profilePicture" accept="image/*">
      <button type="button" id="uploadButton" class="btn-outline">Select Image</button>
    </div>
  </div>
  <div class="form-actions">
    <button type="submit" class="btn-primary">Create Account</button>
  </div>
  <div class="form-links">
    <a href="#" id="loginLink">Already have an account? Login</a>
  </div>
</form>

<div id="notification" class="notification"></div>
```

```javascript
import { signUp } from './auth-api.js';

document.addEventListener('DOMContentLoaded', function() {
  const signupForm = document.getElementById('signupForm');
  const notification = document.getElementById('notification');
  const profilePictureInput = document.getElementById('profilePicture');
  const picturePreview = document.getElementById('picturePreview');
  const uploadButton = document.getElementById('uploadButton');
  
  // Handle profile picture selection
  if (profilePictureInput && picturePreview && uploadButton) {
    uploadButton.addEventListener('click', () => profilePictureInput.click());
    
    profilePictureInput.addEventListener('change', function(e) {
      const file = e.target.files[0];
      if (file) {
        if (!file.type.startsWith('image/')) {
          showNotification('Please select an image file', 'error');
          return;
        }
        
        if (file.size > 5 * 1024 * 1024) { // 5MB max
          showNotification('Image size should be less than 5MB', 'error');
          return;
        }
        
        const reader = new FileReader();
        reader.onload = function(event) {
          picturePreview.src = event.target.result;
        };
        reader.readAsDataURL(file);
      }
    });
  }
  
  // Handle form submission
  signupForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const username = document.getElementById('username').value;
    const displayName = document.getElementById('displayName').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    // Basic validation
    if (password !== confirmPassword) {
      showNotification('Passwords do not match', 'error');
      return;
    }
    
    if (password.length < 8) {
      showNotification('Password must be at least 8 characters', 'error');
      return;
    }
    
    try {
      // Show loading state
      const submitButton = this.querySelector('button[type="submit"]');
      const originalText = submitButton.textContent;
      submitButton.disabled = true;
      submitButton.textContent = 'CREATING ACCOUNT...';
      
      // Prepare user data
      const userData = {
        email,
        username,
        displayName,
        password
      };
      
      // Add profile picture if selected
      if (picturePreview && picturePreview.src && !picturePreview.src.includes('default-avatar.svg')) {
        userData.profilePicture = picturePreview.src;
      }
      
      // Call signup API
      const response = await signUp(userData);
      
      // Show success message and recovery key
      let message = 'Account created successfully!';
      if (response.recoveryKey) {
        message += ' Your recovery key is: ' + response.recoveryKey + '. Please save it securely.';
      }
      showNotification(message, 'success');
      
      // Redirect or update UI based on authenticated state
      // Example: window.location.href = '/dashboard';
      
    } catch (error) {
      showNotification(error.message || 'Failed to create account', 'error');
    } finally {
      // Reset button state
      submitButton.disabled = false;
      submitButton.textContent = originalText;
    }
  });
  
  function showNotification(message, type = 'info') {
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
      notification.style.display = 'none';
    }, 5000);
  }
});
```

### Profile Management

```html
<div class="profile-container">
  <div class="profile-header">
    <div class="profile-picture">
      <img id="userAvatar" src="path/to/default-avatar.svg" alt="Profile Picture">
      <button id="changePhotoButton" class="btn-outline">Change Photo</button>
      <input type="file" id="photoInput" accept="image/*" style="display:none;">
    </div>
    <div class="profile-info">
      <h2 id="userDisplayName">User Name</h2>
      <p id="userEmail">user@example.com</p>
    </div>
  </div>
  
  <div class="profile-tabs">
    <button class="tab-button active" data-tab="profileSettings">Profile Settings</button>
    <button class="tab-button" data-tab="securitySettings">Security</button>
    <button class="tab-button" data-tab="dangerZone">Account</button>
  </div>
  
  <div class="tab-content">
    <!-- Profile Settings Tab -->
    <div id="profileSettings" class="tab-pane active">
      <form id="profileForm">
        <div class="form-group">
          <label for="username">Username</label>
          <input type="text" id="username" required>
        </div>
        <div class="form-group">
          <label for="displayName">Display Name</label>
          <input type="text" id="displayName" required>
        </div>
        <div class="form-actions">
          <button type="submit" class="btn-primary">Save Changes</button>
        </div>
      </form>
    </div>
    
    <!-- Security Settings Tab -->
    <div id="securitySettings" class="tab-pane">
      <form id="securityForm">
        <div class="form-group">
          <label for="currentPassword">Current Password</label>
          <input type="password" id="currentPassword">
        </div>
        <div class="form-group">
          <label for="newPassword">New Password</label>
          <input type="password" id="newPassword">
        </div>
        <div class="form-group">
          <label for="confirmPassword">Confirm New Password</label>
          <input type="password" id="confirmPassword">
        </div>
        <div class="form-actions">
          <button type="submit" class="btn-primary">Update Password</button>
        </div>
      </form>
      
      <div class="recovery-key-section">
        <h3>Recovery Key</h3>
        <p>Use this key to recover your account if you forget your password.</p>
        <div class="form-group">
          <label for="recoveryKey">Your Recovery Key</label>
          <div class="input-with-button">
            <input type="text" id="recoveryKey" readonly>
            <button id="generateNewKey" class="btn-outline">Generate New Key</button>
          </div>
          <button id="copyKey" class="btn-outline">Copy Key</button>
        </div>
      </div>
    </div>
    
    <!-- Account Tab (Danger Zone) -->
    <div id="dangerZone" class="tab-pane">
      <div class="danger-zone">
        <h3>Delete Account</h3>
        <p>Once you delete your account, there is no going back. Please be certain.</p>
        <button id="deleteAccountButton" class="btn-danger">Delete My Account</button>
      </div>
    </div>
  </div>
</div>

<!-- Delete Account Modal -->
<div id="deleteAccountModal" class="modal">
  <div class="modal-content">
    <div class="modal-header">
      <h3>Delete Account</h3>
      <button class="modal-close">&times;</button>
    </div>
    <div class="modal-body">
      <p>Are you sure you want to delete your account? This action cannot be undone.</p>
      <div class="form-group">
        <label for="deleteConfirmPassword">Enter your password to confirm:</label>
        <input type="password" id="deleteConfirmPassword" required>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn-outline modal-cancel">Cancel</button>
      <button id="confirmDeleteButton" class="btn-danger">Delete My Account</button>
    </div>
  </div>
</div>

<div id="notification" class="notification"></div>
```

```javascript
import { getUserProfile, updateUserProfile, deleteAccount, logout } from './auth-api.js';

document.addEventListener('DOMContentLoaded', async function() {
  const notification = document.getElementById('notification');
  
  // Tab switching functionality
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabPanes = document.querySelectorAll('.tab-pane');
  
  tabButtons.forEach(button => {
    button.addEventListener('click', function() {
      const targetTab = this.getAttribute('data-tab');
      
      // Update active state for buttons
      tabButtons.forEach(btn => btn.classList.remove('active'));
      this.classList.add('active');
      
      // Show the selected tab content
      tabPanes.forEach(pane => {
        pane.classList.remove('active');
        if (pane.id === targetTab) {
          pane.classList.add('active');
        }
      });
    });
  });
  
  // Profile picture handling
  const changePhotoButton = document.getElementById('changePhotoButton');
  const photoInput = document.getElementById('photoInput');
  const userAvatar = document.getElementById('userAvatar');
  
  if (changePhotoButton && photoInput) {
    changePhotoButton.addEventListener('click', () => photoInput.click());
    
    photoInput.addEventListener('change', function(e) {
      const file = e.target.files[0];
      if (file) {
        if (!file.type.startsWith('image/')) {
          showNotification('Please select an image file', 'error');
          return;
        }
        
        if (file.size > 5 * 1024 * 1024) { // 5MB max
          showNotification('Image size should be less than 5MB', 'error');
          return;
        }
        
        const reader = new FileReader();
        reader.onload = function(event) {
          userAvatar.src = event.target.result;
        };
        reader.readAsDataURL(file);
      }
    });
  }
  
  // Load user profile
  try {
    const { user } = await getUserProfile();
    
    if (user) {
      // Update UI with user data
      document.getElementById('userDisplayName').textContent = user.displayName;
      document.getElementById('userEmail').textContent = user.email;
      document.getElementById('username').value = user.username;
      document.getElementById('displayName').value = user.displayName;
      
      if (user.profilePicture) {
        userAvatar.src = user.profilePicture;
      }
    }
  } catch (error) {
    showNotification('Failed to load profile: ' + error.message, 'error');
  }
  
  // Handle profile form submission
  const profileForm = document.getElementById('profileForm');
  profileForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const displayName = document.getElementById('displayName').value;
    
    try {
      const submitButton = this.querySelector('button');
      const originalText = submitButton.textContent;
      submitButton.disabled = true;
      submitButton.textContent = 'Saving...';
      
      // Prepare update data
      const updateData = { username, displayName };
      
      // Include new profile picture if changed
      if (userAvatar && userAvatar.src && !userAvatar.src.includes('default-avatar')) {
        updateData.profilePicture = userAvatar.src;
      }
      
      // Call API to update profile
      const response = await updateUserProfile(updateData);
      showNotification('Profile updated successfully', 'success');
      
    } catch (error) {
      showNotification(error.message || 'Failed to update profile', 'error');
    } finally {
      submitButton.disabled = false;
      submitButton.textContent = originalText;
    }
  });
  
  // Handle security form submission
  const securityForm = document.getElementById('securityForm');
  securityForm.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (newPassword !== confirmPassword) {
      showNotification('New passwords do not match', 'error');
      return;
    }
    
    if (newPassword && newPassword.length < 8) {
      showNotification('Password must be at least 8 characters', 'error');
      return;
    }
    
    try {
      const submitButton = this.querySelector('button');
      const originalText = submitButton.textContent;
      submitButton.disabled = true;
      submitButton.textContent = 'Updating...';
      
      // Call API to update password
      const response = await updateUserProfile({
        currentPassword,
        newPassword
      });
      
      showNotification('Password updated successfully', 'success');
      
      // Clear password fields
      document.getElementById('currentPassword').value = '';
      document.getElementById('newPassword').value = '';
      document.getElementById('confirmPassword').value = '';
      
    } catch (error) {
      showNotification(error.message || 'Failed to update password', 'error');
    } finally {
      submitButton.disabled = false;
      submitButton.textContent = originalText;
    }
  });
  
  // Handle recovery key generation
  const generateNewKeyButton = document.getElementById('generateNewKey');
  generateNewKeyButton.addEventListener('click', async function() {
    const currentPassword = prompt('Enter your current password to generate a new recovery key:');
    
    if (!currentPassword) return;
    
    try {
      const originalText = this.textContent;
      this.disabled = true;
      this.textContent = 'Generating...';
      
      // Call API to generate new key
      const response = await updateUserProfile({
        currentPassword,
        generateNewRecoveryKey: true
      });
      
      if (response.recoveryKey) {
        document.getElementById('recoveryKey').value = response.recoveryKey;
        showNotification('New recovery key generated successfully', 'success');
      }
    } catch (error) {
      showNotification(error.message || 'Failed to generate new key', 'error');
    } finally {
      this.disabled = false;
      this.textContent = originalText;
    }
  });
  
  // Copy recovery key to clipboard
  const copyKeyButton = document.getElementById('copyKey');
  copyKeyButton.addEventListener('click', function() {
    const recoveryKeyInput = document.getElementById('recoveryKey');
    recoveryKeyInput.select();
    document.execCommand('copy');
    showNotification('Recovery key copied to clipboard', 'success');
  });
  
  // Delete account modal
  const deleteAccountButton = document.getElementById('deleteAccountButton');
  const deleteAccountModal = document.getElementById('deleteAccountModal');
  const confirmDeleteButton = document.getElementById('confirmDeleteButton');
  
  deleteAccountButton.addEventListener('click', function() {
    deleteAccountModal.style.display = 'block';
  });
  
  // Close modal when clicking close button or cancel
  const closeButtons = deleteAccountModal.querySelectorAll('.modal-close, .modal-cancel');
  closeButtons.forEach(button => {
    button.addEventListener('click', function() {
      deleteAccountModal.style.display = 'none';
    });
  });
  
  // Handle account deletion
  confirmDeleteButton.addEventListener('click', async function() {
    const password = document.getElementById('deleteConfirmPassword').value;
    
    if (!password) {
      showNotification('Please enter your password to confirm', 'error');
      return;
    }
    
    try {
      const originalText = this.textContent;
      this.disabled = true;
      this.textContent = 'Deleting...';
      
      // Call API to delete account
      await deleteAccount(password);
      
      showNotification('Account deleted successfully', 'success');
      
      // Redirect to home page after short delay
      setTimeout(() => {
        window.location.href = '/';
      }, 2000);
      
    } catch (error) {
      showNotification(error.message || 'Failed to delete account', 'error');
      this.disabled = false;
      this.textContent = originalText;
    }
  });
  
  function showNotification(message, type = 'info') {
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
      notification.style.display = 'none';
    }, 5000);
  }
});
```

## Authentication State Management

Here's how to manage authentication state throughout your application:

```javascript
import { isAuthenticated, getCurrentUser } from './auth-api.js';

// Function to check auth state and update UI accordingly
function updateAuthUI() {
  const authContainer = document.getElementById('authContainer');
  const userMenuContainer = document.getElementById('userMenuContainer');
  
  if (isAuthenticated()) {
    // User is logged in
    const user = getCurrentUser();
    
    // Hide login/signup buttons
    authContainer.style.display = 'none';
    
    // Show user menu
    userMenuContainer.style.display = 'block';
    
    // Update user info in the menu
    const userNameElement = document.getElementById('userMenuName');
    const userAvatarElement = document.getElementById('userMenuAvatar');
    
    if (userNameElement) {
      userNameElement.textContent = user.displayName || user.username;
    }
    
    if (userAvatarElement && user.profilePicture) {
      userAvatarElement.src = user.profilePicture;
    }
  } else {
    // User is not logged in
    authContainer.style.display = 'block';
    userMenuContainer.style.display = 'none';
  }
}

// Call this function when the page loads
document.addEventListener('DOMContentLoaded', updateAuthUI);

// Example of protecting routes
function requireAuth(redirectPath = '/login') {
  if (!isAuthenticated()) {
    window.location.href = redirectPath;
  }
}

// Use this at the top of scripts for pages that require authentication
// Example: requireAuth();
```

## Protected Routes / Content

To protect content or pages that require authentication:

```javascript
import { isAuthenticated } from './auth-api.js';

document.addEventListener('DOMContentLoaded', function() {
  // Check authentication status
  if (!isAuthenticated()) {
    // Show login required message
    const contentContainer = document.getElementById('protectedContent');
    contentContainer.innerHTML = `
      <div class="auth-required">
        <h2>Login Required</h2>
        <p>You need to login to access this content.</p>
        <button id="loginButton" class="btn-primary">Login</button>
      </div>
    `;
    
    // Add event listener to login button
    document.getElementById('loginButton').addEventListener('click', function() {
      // Open login modal or redirect to login page
      showLoginModal(); // or window.location.href = '/login';
    });
    
    return; // Stop execution of the rest of the script
  }
  
  // If authenticated, load protected content
  loadProtectedContent();
});

// Function to load content only for authenticated users
function loadProtectedContent() {
  // Your code to load and display protected content
}
```

## Customization Tips

1. **Match Your Site's Design**: Use your existing CSS classes and styling for forms and components.
2. **Modal vs. Page Navigation**: For a smoother user experience, consider implementing login and signup forms in modal dialogs rather than separate pages.
3. **Error Handling**: Implement consistent error handling across all UI components.
4. **Loading States**: Always show loading states during API calls to improve user experience.
5. **Token Renewal**: Implement a token refresh mechanism for long user sessions.

## Complete Code Examples

For complete code examples and components, refer to the following files in this repository:

- `/public/js/auth.js` - Core authentication utilities
- `/public/js/login.js` - Login implementation
- `/public/js/signup.js` - Signup implementation
- `/public/js/profile.js` - Profile management implementation
