require 'pg'
require 'csv'

class WebsiteImporter
  def import
    puts 'Running importer...'
    conn = get_db_connection
    create_prepared_insert(conn, 'website.phishy_site')
    zip_array =  []
    begin
      CSV.foreach('./suspicious_domains.log') do |row|
          begin
            puts "Inserting: #{row[0]}"
            conn.exec_prepared(
              'insert_phishy_site',
              [row[0], row[1], row[2]]
            )
            puts "\tSuccess"
          rescue Exception
            puts "\tFail"
          end
      end
    rescue Exception
        puts "Importer didn't start, something went wrong..."
    end
  end

  private

  def get_db_connection
    PG::Connection.open(
      host: ENV.fetch('DB_HOST'),
      port: ENV.fetch('DB_PORT'),
      dbname: ENV.fetch('DB_NAME'),
      user: ENV.fetch('DB_USER'),
      password: ENV.fetch('DB_PASS')
    )
  end

  def create_prepared_insert(conn, table_name)
    conn.prepare(
      'insert_phishy_site',
      "insert into #{table_name} (url, score, category)
       values ($1, $2, $3)")
  end
end
