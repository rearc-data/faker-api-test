# Faker API Test

A Proof of Concept (POC) Mock API built with Node.js and FakerJS. This application generates synthetic cyber event data designed for volume and load testing.

It is inspired by the structure of standard security APIs and is configured to run natively as a **Databricks App**.

## 🚀 Features

* **Synthetic Data Generation:** Uses FakerJS to create realistic, randomized data payloads (e.g., IPs, timestamps, event severities).
* **Volume Testing Ready:** Designed to handle requests for bulk data generation to test downstream data pipelines or dashboards.
* **Databricks Native:** Includes an `app.yaml` configuration for seamless deployment as a Databricks App.

## 📁 Repository Structure

* `app.js` - The main Express server and API route definitions.
* `app.yaml` - The configuration file required by Databricks Apps to start the compute resources.
* `package.json` - Defines the project dependencies (Express, FakerJS) and scripts.

## 🛠️ Local Development

If you want to run this API on your local machine outside of Databricks:

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/ashwin975/faker-api-test.git](https://github.com/ashwin975/faker-api-test.git)
   cd faker-api-test
