import streamlit as st
import joblib
import requests
from bs4 import BeautifulSoup
import re
import tldextract
import whois
import datetime

# Load your pre-trained model with selected features
# model = joblib.load('model_feature_selected.joblib')
model = joblib.load('model_feature_selected.joblib')
def extract_features(url):
    try:
        # Fetch HTML content of the URLs
        response = requests.get(url)
        html_content = response.text

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        # Initialize variables to store feature values
        features = []

        # Feature 1: Length of the URL
        features.append(len(url))

        # Feature 2: Length of the hostname
        parsed_url = tldextract.extract(url)
        features.append(len(parsed_url.domain + '.' + parsed_url.suffix))

        # Feature 3: Number of dots in the URL
        features.append(url.count('.'))

        # Feature 4: Number of hyphens in the URL
        features.append(url.count('-'))

        # Feature 5: Number of slashes in the URL
        features.append(url.count('/'))

        # Feature 6: Presence of 'www' in the URL
        features.append(1 if parsed_url.subdomain == 'www' else 0)

        # Feature 7: Ratio of digits in the URL
        if len(url) > 0:
            num_digits = sum(c.isdigit() for c in url)
            features.append(num_digits / len(url))
        else:
            features.append(0)  # Set default value if URL length is zero

        # Extract text content from the webpage
        text_content = soup.get_text()

        # Feature 8: Length of words in the raw text
        words_raw = re.findall(r'\b\w+\b', text_content)
        features.append(len(words_raw))

        # Feature 9: Character repeat rate
        repeat_chars = re.findall(r'(.)\1+', text_content)
        features.append(len(repeat_chars))

        # Feature 10: Shortest word length in the hostname
        features.append(min(len(word) for word in parsed_url.domain.split('.')))

        # Feature 11: Shortest word length in the URL path
        if parsed_url.suffix:
            # Get the path from the URL string
            url_path = url.split(parsed_url.suffix)[1]
            path_words = [word for word in url_path.split('/') if word]
            if path_words:
                features.append(min(len(word) for word in path_words))
            else:
                features.append(0)
        else:
            features.append(0)  # Set default value if suffix is empty


        # Feature 12: Longest word length in the raw text
        if words_raw:
            features.append(max(len(word) for word in words_raw))
        else:
            features.append(0)

        # Feature 13: Longest word length in the hostname
        if parsed_url.domain:
            features.append(max(len(word) for word in parsed_url.domain.split('.')))
        else:
            features.append(0)

        # Feature 14: Longest word length in the URL path
        if parsed_url.suffix:
            # Get the path from the URL string
            url_path = url.split(parsed_url.suffix)[1]
            path_words = [word for word in url_path.split('/') if word]
            if path_words:  # Check if path_words is not empty
                features.append(max(len(word) for word in path_words))
            else:
                features.append(0)  # Set default value if path_words is empty
        else:
            features.append(0)  # Set default value if suffix is empty


        # Feature 15: Average word length in the raw text
        if len(words_raw) > 0:
            features.append(sum(len(word) for word in words_raw) / len(words_raw))
        else:
            features.append(0)  # Set default value if words_raw list is empty

        # Feature 16: Average word length in the hostname
        if len(parsed_url.domain.split('.')) > 0:
            features.append(sum(len(word) for word in parsed_url.domain.split('.')) / len(parsed_url.domain.split('.')))
        else:
            features.append(0)  # Set default value if parsed_url.domain.split('.') list is empty

        # Feature 17: Average word length in the URL path
        if len(path_words) > 0:
            features.append(sum(len(word) for word in path_words) / len(path_words))
        else:
            features.append(0)  # Set default value if path_words list is empty

        # Feature 18: Presence of phishing hints in the raw text
        phishing_hints = ['click here', 'free', 'limited time', 'urgent', 'password']
        phishing_hint_count = sum(text_content.lower().count(hint) for hint in phishing_hints)
        features.append(phishing_hint_count)

        # Feature 19: Number of hyperlinks
        hyperlinks = soup.find_all('a')
        features.append(len(hyperlinks))

        # Feature 20: Ratio of internal hyperlinks to total hyperlinks
        internal_hyperlinks = [link for link in hyperlinks if url in link.get('href')]
        ratio_intHyperlinks = len(internal_hyperlinks) / len(hyperlinks) if len(hyperlinks) > 0 else 0
        features.append(ratio_intHyperlinks)

        # Feature 21: Ratio of external hyperlinks to total hyperlinks
        ratio_extHyperlinks = 1 - ratio_intHyperlinks
        features.append(ratio_extHyperlinks)

        # Feature 22: Ratio of external redirections to total hyperlinks
        external_redirections = [link for link in hyperlinks if parsed_url.domain not in link.get('href')]
        ratio_extRedirection = len(external_redirections) / len(hyperlinks) if len(hyperlinks) > 0 else 0
        features.append(ratio_extRedirection)

        # Feature 23: Number of links within tags
        links_in_tags = soup.find_all(['a', 'link', 'area'])
        features.append(len(links_in_tags))

        # Feature 24: Ratio of internal media to total media
        media_tags = soup.find_all(['img', 'audio', 'video', 'source', 'track'])
        internal_media = [media for media in media_tags if url in media.get('src')]
        ratio_intMedia = len(internal_media) / len(media_tags) if len(media_tags) > 0 else 0
        features.append(ratio_intMedia)

        # Feature 25: Ratio of external media to total media
        ratio_extMedia = 1 - ratio_intMedia
        features.append(ratio_extMedia)

        # Feature 26: Presence of safe anchor text
        safe_anchor_text = ['contact', 'home', 'about', 'services', 'blog']
        safe_anchor_count = sum(link.text.lower() in safe_anchor_text for link in links_in_tags)
        features.append(safe_anchor_count)

        # Fetch WHOIS information
        domain_info = whois.whois(url)

        # Feature 27: Domain registration length
        expiration_date = domain_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = max(expiration_date)
        registration_length = (expiration_date - datetime.datetime.now()).days
        features.append(registration_length)

        # Feature 28: Domain age
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = min(creation_date)
        domain_age = (datetime.datetime.now() - creation_date).days
        features.append(domain_age)

        # Feature 29: Web traffic (example using an external API)
        # Example using SimilarWeb API
        def get_web_traffic(parsed_url):
            api_key = 'YOUR_API_KEY'  # Replace with your actual API key
            url = f'https://api.similarweb.com/v1/website/{parsed_url.domain}.{parsed_url.suffix}/total-traffic-and-engagement/visits?api_key={api_key}'
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    web_traffic = response.json().get('visits')
                    return web_traffic
                else:
                    print("Failed to fetch web traffic data:", response.text)
                    return None
            except Exception as e:
                print("Error fetching web traffic data:", e)
                return None

        # Feature 30: Google index status (example using Google Search Console API)
        def get_google_index_status(parsed_url):
            api_key = 'YOUR_API_KEY'  # Replace with your actual API key
            property_id = 'YOUR_PROPERTY'  # Replace with your actual property ID
            url = f'https://www.googleapis.com/webmasters/v3/sites/{parsed_url.domain}.{parsed_url.suffix}/searchAnalytics/query?api_key={api_key}&startDate=2020-01-01&endDate=2020-12-31&dimensions=query&searchType=web&rowLimit=1&startRow=0&aggregationType=auto&dimensionFilterGroups=[{{}}]'
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    indexed_pages = response.json().get('total')
                    return indexed_pages
                else:
                    print("Failed to fetch Google index status:", response.text)
                    return None
            except Exception as e:
                print("Error fetching Google index status:", e)
                return None

        # Use the functions to get web traffic and Google index status
        web_traffic = get_web_traffic(parsed_url)
        if web_traffic is not None:
            features.append(web_traffic)
        else:
            features.append(0)  # Set default value if web traffic data is not available

        indexed_pages = get_google_index_status(parsed_url)
        if indexed_pages is not None:
            features.append(indexed_pages)
        else:
            features.append(0)  # Set default value if Google index status data is not available


        return features
    except requests.exceptions.ConnectionError as e:
        print("Error connecting to the URL:", e)
        st.error("Error connecting to the URL. Please make sure the URL is valid and try again.")
        return None

    except requests.exceptions.HTTPError as e:
        print("HTTP error occurred:", e)
        st.error("HTTP error occurred. Please try again later.")
        return None
    except requests.exceptions.RequestException as e:
        st.error("Error occurred while processing the URL. Please try again later.")
        return None
    except Exception as e:
        print("Error occurred:", e)
        st.error("An error occurred. Please try again later.")
        return None

# Define function to make predictions
def predict(features):
    # Make prediction using the loaded model
    prediction = model.predict([features])[0]
    return prediction

# Function to simulate user authentication (dummy function)
def authenticate(username, password):
    return username == "admin" and password == "admin123"
def login_page():
    st.title("Admin Login")

    # Input fields for username and password
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    # Login button
    if st.button("Login"):
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            st.success("Login successful!")
            st.write("Welcome, admin!")
            # Add redirection or other actions upon successful login
        else:
            st.error("Invalid username or password")
# def admin_page():
#     st.title("Admin Page")

#     # Admin features
#     st.write("Admin features:")
#     st.write("- Update the previously loaded dataset of analyzed websites")
#     st.write("- Manage and store user data (IP address, device name)")
def admin_page():
    st.title("Admin Page")

    # Create tabs for different admin features
    tab_selection = st.radio("Select feature:", ["Update Dataset", "Manage Users"])

    # Render different content based on the selected tab
    if tab_selection == "Update Dataset":
        st.write("Feature: Update the previously loaded dataset of analyzed websites")
        # Add code for updating the dataset here
    elif tab_selection == "Manage Users":
        st.write("Feature: Manage and store user data (IP address, device name)")
        # Add code for managing users here
    else:
        st.error("Invalid tab selection")
# Define your Streamlit app
# Define admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

def main():
     
    page = st.sidebar.selectbox("Select Page", ["Home", "Admin"])

    if page == "Home":
        st.title('SpoofSafe')
        st.text('Safeguarding clicks, one detection at a time')
        # Add input field for user to enter URL
        url = st.text_input("Enter the URL:")
        # Displaying the search url
        st.write("You entered:",url)
    
        if st.button('Check for Phishing'):
            # Extract features from the URL
            features = extract_features(url)
            print(features)
            if features is not None:
                st.subheader('Extracted Features:')
                st.write(features)
                # Call predict function to get prediction
                prediction = predict(features)
            
                # Display prediction result
                if prediction == 1:
                    st.error('This website might be a phishing website!')
                elif prediction == 0:
                    st.success('This website appears to be safe.')
                else:
                    st.warning('Unable to make a prediction.')
        
    elif page == "Admin":
        login_page()
    #     if authenticate("admin", "admin123"):
    #         st.write("Logged in")
    # else:
    #     st.error("Page not found")

# Run your Streamlit app
if __name__ == '__main__':
    main()

