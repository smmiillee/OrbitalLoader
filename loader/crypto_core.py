name: Protect EXE

on:
  workflow_dispatch:
    inputs:
      customer_id:
        description: 'Customer ID for license'
        required: true
      expiry_days:
        description: 'License validity (days)'
        default: '365'
      features:
        description: 'Feature flags'
        default: 'basic'

jobs:
  protect:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Find EXE in incoming/
        id: find_exe
        run: |
          EXE=$(find ./incoming -type f | head -1)
          if [ -z "$EXE" ]; then
            echo "No file found in ./incoming/"
            echo "Please put your EXE in the incoming/ folder"
            exit 1
          fi
          echo "exe_path=$EXE" >> $GITHUB_OUTPUT
          echo "Found: $EXE"
      
      - name: Protect with loader
        env:
          LOADER_MASTER_SECRET: ${{ secrets.LOADER_MASTER_SECRET }}
        run: |
          python -m loader protect-exe "${{ steps.find_exe.outputs.exe_path }}" \
            -o ./protected \
            --customer "${{ github.event.inputs.customer_id }}" \
            --days ${{ github.event.inputs.expiry_days }} \
            --features ${{ github.event.inputs.features }}
      
      - name: Upload protected build
        uses: actions/upload-artifact@v4
        with:
          name: protected-${{ github.event.inputs.customer_id }}
          path: protected/
          retention-days: 30
      
      - name: Summary
        run: |
          echo "## Protected Build Complete" >> $GITHUB_STEP_SUMMARY
          echo "- Customer: ${{ github.event.inputs.customer_id }}" >> $GITHUB_STEP_SUMMARY
          echo "- Download artifact: \`protected-${{ github.event.inputs.customer_id }}\`" >> $GITHUB_STEP_SUMMARY
