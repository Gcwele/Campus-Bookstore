from bookstore import create_app, render_template

app = create_app()

@app.route('/about')
def about_page():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)
